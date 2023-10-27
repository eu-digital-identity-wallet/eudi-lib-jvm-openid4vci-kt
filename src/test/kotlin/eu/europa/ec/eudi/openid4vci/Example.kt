/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL
import java.time.Instant

val SdJwtVC_CredentialOffer = """
    {
      "credential_issuer": "http://localhost:8080",
      "credentials": [
        "eu.europa.ec.eudiw.pid_vc_sd_jwt"
      ],
      "grants": {
        "authorization_code": {}
      }
    }
""".trimIndent()

val MsoMdoc_CredentialOffer = """
    {
      "credential_issuer": "http://localhost:8080",
      "grants": {
        "authorization_code": {}
      },
      "credentials": [
        "eu.europa.ec.eudiw.pid_mso_mdoc"        
      ]
    }
""".trimIndent()

fun main(): Unit = runBlocking {
    val coUrl = "http://localhost:8080/credentialoffer?credential_offer=$MsoMdoc_CredentialOffer"
    val wallet = Wallet.ofUser(ActingUser("babis", "babis"))
    val credential = wallet.issueOfferedCredential(coUrl)

    println("--> Issued credential : $credential")
}

data class ActingUser(
    val username: String,
    val password: String,
)

private class Wallet(
    val actingUser: ActingUser,
) {

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "wallet-dev",
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
    )

    suspend fun issueOfferedCredential(coUrl: String): String {
        val ktorHttpClient = defaultHttpClientFactory()
        val credentialOfferRequestResolver = CredentialOfferRequestResolver(
            httpGet = { url ->
                runCatching {
                    ktorHttpClient.get(url).body<String>()
                }
            },
        )

        val offer = credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        val issuer = Issuer.ktor(
            offer.authorizationServerMetadata,
            offer.credentialIssuerMetadata,
            vciWalletConfiguration,
        )

        // Authorize with auth code flow
        val authorized = authorizeRequestWithAuthCodeUseCase(issuer, offer)

        val outcome = when (authorized) {
            is AuthorizedRequest.NoProofRequired -> {
                noProofRequiredSubmissionUseCase(issuer, authorized, offer)
            }
            is AuthorizedRequest.ProofRequired -> {
                proofRequiredSubmissionUseCase(issuer, authorized, offer, authorized.cNonce.toJwtProof())
            }
        }

        return outcome
    }

    private suspend fun authorizeRequestWithAuthCodeUseCase(issuer: Issuer, offer: CredentialOffer): AuthorizedRequest {
        with(issuer) {
            println("--> Placing PAR to AS server's endpoint ${offer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI}")

            val parPlaced = pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()

            println("--> Placed PAR. Get authorization code URL is: ${parPlaced.getAuthorizationCodeURL.url.value}")

            val authorizationCode = loginUserAndGetAuthCode(
                parPlaced.getAuthorizationCodeURL.url.value.toURL(),
                actingUser,
            ) ?: error("Could not retrieve authorization code")

            println("--> Authorization code retrieved: $authorizationCode")

            val authorized = parPlaced
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()

            println("--> Authorization code exchanged with access token : ${authorized.token.accessToken}")

            return authorized
        }
    }

    private suspend fun proofRequiredSubmissionUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest.ProofRequired,
        offer: CredentialOffer,
        proof: Proof.Jwt,
    ): String {
        with(issuer) {
            val requestOutcome = authorized.requestSingle(offer.credentials[0], null, proof).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val result = requestOutcome.response.credentialResponses.get(0)
                    when (result) {
                        is CredentialIssuanceResponse.Result.Complete -> result.credential
                        is CredentialIssuanceResponse.Result.Deferred -> result.transactionId
                    }
                }

                is SubmittedRequest.Failed -> {
                    requestOutcome.error.raise()
                }

                is SubmittedRequest.InvalidProof -> TODO()
            }
        }
    }

    private suspend fun noProofRequiredSubmissionUseCase(
        issuer: Issuer,
        noProofRequiredState: AuthorizedRequest.NoProofRequired,
        offer: CredentialOffer,
    ): String {
        with(issuer) {
            val requestOutcome = noProofRequiredState.requestSingle(offer.credentials[0], null).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val result = requestOutcome.response.credentialResponses.get(0)
                    when (result) {
                        is CredentialIssuanceResponse.Result.Complete -> result.credential
                        is CredentialIssuanceResponse.Result.Deferred -> result.transactionId
                    }
                }

                is SubmittedRequest.InvalidProof -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        noProofRequiredState.handleInvalidProof(requestOutcome.cNonce),
                        offer,
                        requestOutcome.cNonce.toJwtProof(),
                    )
                }

                is SubmittedRequest.Failed -> {
                    requestOutcome.error.raise()
                }
            }
        }
    }

    private fun httpClientWithHttpCookiesFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) { json() }
            install(HttpCookies)
        }

    private fun defaultHttpClientFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) {
                json(
                    json = Json { ignoreUnknownKeys = true },
                )
            }
        }

    private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
        val client = httpClientWithHttpCookiesFactory()

        val loginUrl = HttpGet { url ->
            runCatching {
                client.get(url).body<String>()
            }
        }.get(getAuthorizationCodeUrl).getOrThrow().extractASLoginUrl()

        return HttpFormPost { url, formParameters ->
            val response = client.submitForm(
                url = url.toString(),
                formParameters = Parameters.build {
                    formParameters.entries.forEach { append(it.key, it.value) }
                },
            )
            val redirectLocation = response.headers.get("Location").toString()
            URLBuilder(redirectLocation).parameters.get("code")
        }.post(
            loginUrl,
            mapOf(
                "username" to actingUser.username,
                "password" to actingUser.password,
            ),
        )
    }

    private fun String.extractASLoginUrl(): URL {
        val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
        val action = form.attr("action")
        return URL(action)
    }

    private fun CNonce.toJwtProof(): Proof.Jwt {
        val jsonObject =
            buildJsonObject {
                put("iss", "wallet_client_id")
                put("iat", Instant.now().epochSecond)
                put("aud", CREDENTIAL_ISSUER_PUBLIC_URL)
                put("nonce", value)
            }
        val jsonStr = Json.encodeToString(jsonObject)
        return Proof.Jwt(
            jwt = PlainJWT(JWTClaimsSet.parse(jsonStr)),
        )
    }

    companion object {
        fun ofUser(actingUser: ActingUser) = Wallet(actingUser)
    }
}
