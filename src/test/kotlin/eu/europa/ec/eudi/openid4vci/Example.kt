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

val CredentialIssuer_URL = "http://localhost:8080"
val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
val PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"

val SdJwtVC_CredentialOffer = """
    {
      "credential_issuer": "$CredentialIssuer_URL",
      "credentials": [ "$PID_SdJwtVC_SCOPE" ],
      "grants": {
        "authorization_code": {}
      }
    }
""".trimIndent()

val MsoMdoc_CredentialOffer = """
    {
      "credential_issuer": "$CredentialIssuer_URL",
      "grants": {
        "authorization_code": {}
      },
      "credentials": [ "$PID_MsoMdoc_SCOPE" ]
    }
""".trimIndent()

val config = WalletOpenId4VCIConfig(
    clientId = "wallet-dev",
    authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
)

fun main(): Unit = runBlocking {
    val bindingKey = BindingKey.Jwk(
        algorithm = JWSAlgorithm.RS256,
        jwk = ProofBuilder.randomRSASigningKey(2048),
    )

    val user = ActingUser("babis", "babis")
    val wallet = Wallet.ofUser(user, bindingKey)

    WalletInitiatedIssuanceWithOffer(wallet)
    WalletInitiatedIssuanceNoOffer(wallet)
}

private suspend fun WalletInitiatedIssuanceWithOffer(wallet: Wallet) {
    println("[[Scenario: Offer passed to wallet via url]] ")

    val coUrl = "http://localhost:8080/credentialoffer?credential_offer=$SdJwtVC_CredentialOffer"

    val credential = wallet.issueByCredentialOfferUrl(coUrl)

    println("--> Issued credential : $credential \n")
}

private suspend fun WalletInitiatedIssuanceNoOffer(wallet: Wallet) {
    println("[[Scenario: No offer passed, wallet initiates issuance by credetial scopes]]")

    val credential = wallet.issueByScope(PID_SdJwtVC_SCOPE)

    println("--> Issued credential : $credential \n")
}

data class ActingUser(
    val username: String,
    val password: String,
)

private class Wallet(
    val actingUser: ActingUser,
    val bindingKey: BindingKey,
) {

    suspend fun issueByScope(scope: String): String {
        val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
        val issuerMetadata = CredentialIssuerMetadataResolver.ktor().resolve(credentialIssuerIdentifier).getOrThrow()
        val authServerMetadata = AuthorizationServerMetadataResolver.ktor().resolve(issuerMetadata.authorizationServer).getOrThrow()

        val offer = CredentialOffer(
            credentialIssuerIdentifier = credentialIssuerIdentifier,
            credentials = listOf(CredentialMetadata.ByScope(Scope.of(scope))),
            credentialIssuerMetadata = issuerMetadata,
            authorizationServerMetadata = authServerMetadata,
        )
        return issueOfferedCredential(offer)
    }

    suspend fun issueByCredentialOfferUrl(coUrl: String): String {
        val offer = httpClientFactory().use { client ->
            val credentialOfferRequestResolver = CredentialOfferRequestResolver(
                httpGet = { url ->
                    runCatching {
                        client.get(url).body<String>()
                    }
                },
            )
            credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        }

        return issueOfferedCredential(offer)
    }

    private suspend fun issueOfferedCredential(offer: CredentialOffer): String {
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

    private suspend fun authorizeRequestWithPreAuthCodeUseCase(
        issuer: Issuer,
        offer: CredentialOffer,
    ): AuthorizedRequest {
        with(issuer) {
            val preAuthorizedCode =
                when (val grants = offer.grants) {
                    is Grants.Both -> grants.preAuthorizedCode
                    is Grants.PreAuthorizedCode -> grants
                    else -> throw IllegalStateException(
                        "Invalid proof: Grants expected should be either Grants.PreAuthorizedCode or Grants.Both",
                    )
                }

            val preAuthorizationCode =
                IssuanceAuthorization.PreAuthorizationCode(preAuthorizedCode.preAuthorizedCode, "")

            val authorizedRequest = authorizeWithPreAuthorizationCode(offer.credentials, preAuthorizationCode).getOrThrow()

            println("--> Pre-authorization code exchanged with access token : ${authorizedRequest.token.accessToken}")

            return authorizedRequest
        }
    }

    private suspend fun proofRequiredSubmissionUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest.ProofRequired,
        offer: CredentialOffer,
    ): String {
        with(issuer) {
            val requestOutcome = authorized.requestSingle(offer.credentials[0], null, bindingKey).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val result = requestOutcome.response.credentialResponses.get(0)
                    when (result) {
                        is CredentialIssuanceResponse.Result.Complete -> result.credential
                        is CredentialIssuanceResponse.Result.Deferred -> result.transactionId
                    }
                }

                is SubmittedRequest.Failed -> {
                    throw requestOutcome.error
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
                    val result = requestOutcome.response.credentialResponses[0]
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
                    )
                }

                is SubmittedRequest.Failed -> throw requestOutcome.error
            }
        }
    }

    private fun httpClientFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) {
                json(
                    json = Json { ignoreUnknownKeys = true },
                )
            }
            install(HttpCookies)
        }

    private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
        httpClientFactory().use { client ->

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

    companion object {
        fun ofUser(actingUser: ActingUser, bindingKey: BindingKey.Jwk) = Wallet(actingUser, bindingKey)
    }
}
