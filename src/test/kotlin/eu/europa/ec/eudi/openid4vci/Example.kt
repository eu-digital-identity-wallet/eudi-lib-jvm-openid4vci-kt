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

import com.nimbusds.jose.JWSAlgorithm
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.lang.IllegalStateException
import java.net.URI
import java.net.URL

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
    val coUrl = "http://localhost:8080/credentialoffer?credential_offer=$SdJwtVC_CredentialOffer"
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

    val config = WalletOpenId4VCIConfig(
        clientId = "wallet-dev",
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
    )

    suspend fun issueOfferedCredential(coUrl: String): String {
        val offer = HttpClientFactory().use { client ->
            val credentialOfferRequestResolver = CredentialOfferRequestResolver(
                httpGet = { url ->
                    runCatching {
                        client.get(url).body<String>()
                    }
                },
            )
            credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        }
        val issuer = Issuer.ktor(
            offer.authorizationServerMetadata,
            offer.credentialIssuerMetadata,
            config,
        )

        // Authorize with auth code flow
        val authorized = authorizeRequestWithAuthCodeUseCase(issuer, offer)
        val outcome = when (authorized) {
            is AuthorizedRequest.NoProofRequired -> {
                noProofRequiredSubmissionUseCase(issuer, authorized, offer)
            }
            is AuthorizedRequest.ProofRequired -> {
                proofRequiredSubmissionUseCase(
                    issuer,
                    authorized,
                    offer,
                    authorized.cNonce.toJwtProof(
                        config.clientId,
                        offer.credentialIssuerIdentifier.value.value.toString(),
                    ),
                )
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

                is SubmittedRequest.InvalidProof ->
                    throw IllegalStateException("Although providing a proof with c_nonce the proof is still invalid")
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
                        requestOutcome.cNonce.toJwtProof(
                            config.clientId,
                            offer.credentialIssuerIdentifier.value.value.toString(),
                        ),
                    )
                }

                is SubmittedRequest.Failed -> {
                    requestOutcome.error.raise()
                }
            }
        }
    }

    private fun HttpClientFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) {
                json(
                    json = Json { ignoreUnknownKeys = true },
                )
            }
            install(HttpCookies)
        }

    private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
        HttpClientFactory().use { client ->

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
    }

    private fun String.extractASLoginUrl(): URL {
        val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
        val action = form.attr("action")
        return URL(action)
    }

    private fun CNonce.toJwtProof(clientId: String, audience: String): Proof.Jwt {
        val jwt = with(ProofBuilder.ofType(ProofType.JWT)) {
            alg(JWSAlgorithm.RS256)
            iss(clientId)
            jwk(ProofBuilder.randomRSAKey())
            aud(audience)
            nonce(value)
            build()
        }
        return Proof.Jwt(jwt)
    }

    companion object {
        fun ofUser(actingUser: ActingUser) = Wallet(actingUser)
    }
}
