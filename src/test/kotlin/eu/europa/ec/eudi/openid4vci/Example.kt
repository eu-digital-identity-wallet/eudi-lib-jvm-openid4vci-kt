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

import com.nimbusds.jose.jwk.Curve
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL

const val CredentialIssuer_URL = "https://eudi.netcompany-intrasoft.com/pid-issuer"
val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()

const val PID_SdJwtVC = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
const val PID_MsoMdoc = "eu.europa.ec.eudiw.pid_mso_mdoc"


val credentialOffer = """
    {
      "credential_issuer": "$CredentialIssuer_URL",
      "credentials": [ "$PID_SdJwtVC", "$PID_MsoMdoc" ],
      "grants": {
        "authorization_code": {}
      }
    }
""".trimIndent()

fun main(): Unit = runTest {
    val proofSigners = mapOf(
        PID_SdJwtVC to CryptoGenerator.rsaProofSigner(),
        PID_MsoMdoc to CryptoGenerator.ecProofSigner(),
    )

    val config = OpenId4VCIConfig(
        clientId = "wallet-dev",
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    )

    val user = ActingUser("tneal", "password")
    val wallet = Wallet.ofUser(user, proofSigners, config)

    walletInitiatedIssuanceWithOffer(wallet)
    walletInitiatedIssuanceNoOffer(wallet)
}

private suspend fun walletInitiatedIssuanceWithOffer(wallet: Wallet) {
    println("[[Scenario: Offer passed to wallet via url]] ")

    val offerUrl = "https://localhost/pid-issuer/credentialoffer?credential_offer=$credentialOffer"
    val credentials = wallet.issueByCredentialOfferUrl(offerUrl)

    println("--> Issued credentials :")
    credentials.onEach { (credentialId, credential) ->
        println("\t [$credentialId] : $credential")
    }
    println()
}

private suspend fun walletInitiatedIssuanceNoOffer(wallet: Wallet) {
    println("[[Scenario: No offer passed, wallet initiates issuance by credential identifiers: $PID_SdJwtVC, $PID_MsoMdoc]]")
    val pidSdjwtVc = wallet.issueByCredentialIdentifier(PID_SdJwtVC)
    println("--> Issued PID $PID_SdJwtVC: $pidSdjwtVc \n")

    val pidMsoMdoc = wallet.issueByCredentialIdentifier(PID_MsoMdoc)
    println("--> Issued PID $PID_MsoMdoc: $pidMsoMdoc \n")
}

data class ActingUser(
    val username: String,
    val password: String,
)

private class Wallet(
    val actingUser: ActingUser,
    val proofSigners: Map<String, DelegatingProofSigner>,
    val config: OpenId4VCIConfig,
) {

    suspend fun issueByCredentialIdentifier(identifier: String): String {
        val (authServerMetadata, issuer) = buildIssuer(credentialIssuerIdentifier, config)
        val credentialIdentifier = CredentialIdentifier(identifier)

        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            listOf(credentialIdentifier),
            authServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        // Authorize with auth code flow
        val outcome =
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired ->
                    noProofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)

                is AuthorizedRequest.ProofRequired ->
                    proofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialIdentifier)
            }

        return outcome
    }

    suspend fun issueByCredentialOfferUrl(coUrl: String): List<Pair<String, String>> {
        val credentialOfferRequestResolver = CredentialOfferRequestResolver(ktorHttpClientFactory = ::httpClientFactory)
        val offer = credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        return issueByCredentialOffer(offer)
    }

    suspend fun issueByCredentialOffer(offer: CredentialOffer): List<Pair<String, String>> {
        val issuerMetadata = offer.credentialIssuerMetadata
        val issuer = Issuer.make(
            authorizationServerMetadata = offer.authorizationServerMetadata,
            config = config,
            issuerMetadata = issuerMetadata,
            ktorHttpClientFactory = ::httpClientFactory,
        )

        // Authorize with auth code flow
        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            offer.credentials,
            offer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        return when (authorizedRequest) {
            is AuthorizedRequest.NoProofRequired ->
                offer.credentials.map { credentialId ->
                    issuanceLog("Requesting issuance of '$credentialId'")
                    val credential = noProofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialId)
                    credentialId.value to credential
                }

            is AuthorizedRequest.ProofRequired ->
                offer.credentials.map { credentialId ->
                    issuanceLog("Requesting issuance of '$credentialId'")
                    val credential = proofRequiredSubmissionUseCase(issuer, authorizedRequest, credentialId)
                    credentialId.value to credential
                }
        }
    }

    private suspend fun authorizeRequestWithAuthCodeUseCase(
        issuer: Issuer,
        credentialMetadata: List<CredentialIdentifier>,
        parEndpoint: String,
    ): AuthorizedRequest =
        with(issuer) {
            authorizationLog("Placing PAR to AS server's endpoint $parEndpoint")

            val parPlaced = pushAuthorizationCodeRequest(credentialMetadata, null).getOrThrow()

            authorizationLog("Placed PAR. Get authorization code URL is: ${parPlaced.getAuthorizationCodeURL.url.value}")

            val authorizationCode = loginUserAndGetAuthCode(
                parPlaced.getAuthorizationCodeURL.url.value,
                actingUser,
            ) ?: error("Could not retrieve authorization code")

            authorizationLog("Authorization code retrieved: $authorizationCode")

            val authorizedRequest = parPlaced
                .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()

            authorizationLog("Authorization code exchanged with access token : ${authorizedRequest.accessToken.accessToken}")

            authorizedRequest
        }

    private suspend fun proofRequiredSubmissionUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest.ProofRequired,
        credentialIdentifier: CredentialIdentifier,
    ): String {
        with(issuer) {
            val proofSigner = proofSigners[credentialIdentifier.value] ?: error("No signer found for credential $credentialIdentifier")
            val requestOutcome =
                authorized.requestSingle(credentialIdentifier, null, proofSigner).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val issuedCredential = requestOutcome.credentials.get(0)
                    when (issuedCredential) {
                        is IssuedCredential.Issued -> issuedCredential.credential
                        is IssuedCredential.Deferred -> {
                            deferredCredentialUseCase(issuer, authorized, issuedCredential)
                        }
                    }
                }

                is SubmittedRequest.Failed -> throw requestOutcome.error

                is SubmittedRequest.InvalidProof ->
                    throw IllegalStateException("Although providing a proof with c_nonce the proof is still invalid")
            }
        }
    }

    private suspend fun deferredCredentialUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest,
        deferred: IssuedCredential.Deferred,
    ): String {
        issuanceLog(
            "Got a deferred issuance response from server with transaction_id ${deferred.transactionId.value}. Retrying issuance...",
        )
        with(issuer) {
            val outcome = authorized.queryForDeferredCredential(deferred).getOrThrow()
            return when (outcome) {
                is DeferredCredentialQueryOutcome.Issued -> outcome.credential.credential
                is DeferredCredentialQueryOutcome.IssuancePending -> throw RuntimeException(
                    "Credential not ready yet. Try after ${outcome.interval}",
                )

                is DeferredCredentialQueryOutcome.Errored -> throw RuntimeException(outcome.error)
            }
        }
    }

    private suspend fun noProofRequiredSubmissionUseCase(
        issuer: Issuer,
        noProofRequiredState: AuthorizedRequest.NoProofRequired,
        credentialIdentifier: CredentialIdentifier,
    ): String {
        with(issuer) {
            val requestOutcome =
                noProofRequiredState.requestSingle(credentialIdentifier, null).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val issuedCredential = requestOutcome.credentials[0]
                    when (issuedCredential) {
                        is IssuedCredential.Issued -> issuedCredential.credential
                        is IssuedCredential.Deferred -> {
                            deferredCredentialUseCase(issuer, noProofRequiredState, issuedCredential)
                        }
                    }
                }

                is SubmittedRequest.InvalidProof -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        noProofRequiredState.handleInvalidProof(requestOutcome.cNonce),
                        credentialIdentifier,
                    )
                }

                is SubmittedRequest.Failed -> throw requestOutcome.error
            }
        }
    }

    @OptIn(InternalAPI::class)
    private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
        return httpClientFactory().use { client ->
            val loginUrl =
                client.get(getAuthorizationCodeUrl).body<String>().extractASLoginUrl()

            val formParameters = mapOf(
                "username" to actingUser.username,
                "password" to actingUser.password,
            )
            val response = client.submitForm(
                url = loginUrl.toString(),
                formParameters = Parameters.build {
                    formParameters.entries.forEach { append(it.key, it.value) }
                },
            )
            val redirectLocation = response.headers.get("Location").toString()
            URLBuilder(redirectLocation).parameters.get("code")
        }
    }

    companion object {
        fun ofUser(actingUser: ActingUser, proofSigners: Map<String, DelegatingProofSigner>, config: OpenId4VCIConfig) =
            Wallet(actingUser, proofSigners, config)
    }
}

private fun authorizationLog(message: String) {
    println("--> [AUTHORIZATION] $message")
}
private fun issuanceLog(message: String) {
    println("--> [ISSUANCE] $message")
}

private suspend fun buildIssuer(
    credentialIssuerIdentifier: CredentialIssuerId,
    config: OpenId4VCIConfig,
): Pair<CIAuthorizationServerMetadata, Issuer> {
    val issuerMetadata =
        CredentialIssuerMetadataResolver(ktorHttpClientFactory = ::httpClientFactory)
            .resolve(credentialIssuerIdentifier).getOrThrow()

    val authServerMetadata =
        AuthorizationServerMetadataResolver(ktorHttpClientFactory = ::httpClientFactory)
            .resolve(issuerMetadata.authorizationServers[0]).getOrThrow()

    val issuer = Issuer.make(
        authorizationServerMetadata = authServerMetadata,
        config = config,
        ktorHttpClientFactory = ::httpClientFactory,
        issuerMetadata = issuerMetadata,
    )
    return Pair(authServerMetadata, issuer)
}

@OptIn(InternalAPI::class)
private fun httpClientFactory(): HttpClient =
    HttpClient(Apache) {
        install(ContentNegotiation) {
            json(
                json = Json { ignoreUnknownKeys = true },
            )
        }
        install(HttpCookies)
        engine {
            customizeClient {
                setSSLContext(
                    SSLContextBuilder.create()
                        .loadTrustMaterial(TrustSelfSignedStrategy())
                        .build(),
                )
                setSSLHostnameVerifier(NoopHostnameVerifier())
            }
        }
    }

private fun String.extractASLoginUrl(): URL {
    val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
    val action = form.attr("action")
    return URL(action)
}
