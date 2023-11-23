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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vci.internal.formats.*
import eu.europa.ec.eudi.openid4vci.internal.formats.MsoMdoc
import eu.europa.ec.eudi.openid4vci.internal.formats.SdJwtVc
import eu.europa.ec.eudi.openid4vci.internal.formats.W3CJsonLdDataIntegrity
import eu.europa.ec.eudi.openid4vci.internal.formats.W3CJsonLdSignedJwt
import eu.europa.ec.eudi.openid4vci.internal.formats.W3CSignedJwt
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL
import java.util.*

const val CredentialIssuer_URL = "https://eudi.netcompany-intrasoft.com/pid-issuer"

const val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
const val PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"
const val OPENID_SCOPE = "openid"

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

val config = OpenId4VCIConfig(
    clientId = "wallet-dev",
    authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
)

fun main(): Unit = runTest {
    val bindingKeys = mapOf(
        PID_SdJwtVC_SCOPE to BindingKey.Jwk(
            algorithm = JWSAlgorithm.RS256,
            jwk = KeyGenerator.randomRSASigningKey(2048),
        ),
        PID_MsoMdoc_SCOPE to BindingKey.Jwk(
            algorithm = JWSAlgorithm.ES256,
            jwk = KeyGenerator.randomECSigningKey(Curve.P_256),
        ),
    )

    val user = ActingUser("tneal", "password")
    val wallet = Wallet.ofUser(user, bindingKeys)

    walletInitiatedIssuanceWithOffer(wallet)
    walletInitiatedIssuanceNoOffer(wallet)
}

private suspend fun walletInitiatedIssuanceWithOffer(wallet: Wallet) {
    println("[[Scenario: Offer passed to wallet via url]] ")

    val coUrl = "https://localhost/pid-issuer/credentialoffer?credential_offer=$SdJwtVC_CredentialOffer"

    val credential = wallet.issueByCredentialOfferUrl(coUrl)

    println("--> Issued credential : $credential \n")
}

private suspend fun walletInitiatedIssuanceNoOffer(wallet: Wallet) {
    println("[[Scenario: No offer passed, wallet initiates issuance by credential scopes: $PID_SdJwtVC_SCOPE, $PID_MsoMdoc_SCOPE]]")
    val pidSdjwtVc = wallet.issueByScope(PID_SdJwtVC_SCOPE)
    println("--> Issued PID in format $PID_SdJwtVC_SCOPE: $pidSdjwtVc \n")

    val pidMsoMdoc = wallet.issueByScope(PID_MsoMdoc_SCOPE)
    println("--> Issued PID in format $PID_MsoMdoc_SCOPE: $pidMsoMdoc \n")
}

data class ActingUser(
    val username: String,
    val password: String,
)

private class Wallet(
    val actingUser: ActingUser,
    val bindingKeys: Map<String, BindingKey>,
) {

    suspend fun issueByScope(scope: String): String {
        val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
        val issuerMetadata =
            CredentialIssuerMetadataResolver(ktorHttpClientFactory = ::httpClientFactory)
                .resolve(credentialIssuerIdentifier).getOrThrow()

        val authServerMetadata =
            AuthorizationServerMetadataResolver(ktorHttpClientFactory = ::httpClientFactory)
                .resolve(issuerMetadata.authorizationServer).getOrThrow()

        val issuer = Issuer.make(
            authorizationServerMetadata = authServerMetadata,
            config = config,
            ktorHttpClientFactory = ::httpClientFactory,
            issuerMetadata = issuerMetadata,
        )

        val credentialMetadata = CredentialMetadata.ByScope(Scope(scope))
        val openIdScope = CredentialMetadata.ByScope(Scope(OPENID_SCOPE))

        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            listOf(credentialMetadata, openIdScope),
            authServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        // Authorize with auth code flow
        val outcome =
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    noProofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        credentialMetadata,
                    )
                }

                is AuthorizedRequest.ProofRequired -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        credentialMetadata,
                    )
                }
            }

        return outcome
    }

    suspend fun issueByCredentialOfferUrl(coUrl: String): String {
        val credentialOfferRequestResolver = CredentialOfferRequestResolver(ktorHttpClientFactory = ::httpClientFactory)
        val offer = credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        return issueByCredentialOffer(offer)
    }

    suspend fun issueByCredentialOffer(offer: CredentialOffer): String {
        val issuer = Issuer.make(
            authorizationServerMetadata = offer.authorizationServerMetadata,
            config = config,
            issuerMetadata = offer.credentialIssuerMetadata,
            ktorHttpClientFactory = ::httpClientFactory,
        )

        val openIdScope = CredentialMetadata.ByScope(Scope(OPENID_SCOPE))

        // Authorize with auth code flow
        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            offer.credentials + openIdScope,
            offer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        val outcome =
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    noProofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        offer.credentials[0],
                    )
                }

                is AuthorizedRequest.ProofRequired -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        offer.credentials[0],
                    )
                }
            }

        return outcome
    }

    private suspend fun authorizeRequestWithAuthCodeUseCase(
        issuer: Issuer,
        credentialMetadata: List<CredentialMetadata>,
        parEndpoint: String,
    ): AuthorizedRequest =
        with(issuer) {
            println("--> Placing PAR to AS server's endpoint $parEndpoint")

            val parPlaced = pushAuthorizationCodeRequest(credentialMetadata, null).getOrThrow()

            println("--> Placed PAR. Get authorization code URL is: ${parPlaced.getAuthorizationCodeURL.url.value}")

            val authorizationCode = loginUserAndGetAuthCode(
                parPlaced.getAuthorizationCodeURL.url.value.toURL(),
                actingUser,
            ) ?: error("Could not retrieve authorization code")

            println("--> Authorization code retrieved: $authorizationCode")

            val authorizedRequest = parPlaced
                .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()

            println("--> Authorization code exchanged with access token : ${authorizedRequest.accessToken.accessToken}")

            authorizedRequest
        }

    private suspend fun proofRequiredSubmissionUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest.ProofRequired,
        credentialMetadata: CredentialMetadata,
    ): String {
        with(issuer) {
            val scope = credentialMetadata.scope()
            val bindingKey = bindingKeys[scope] ?: error("No binding key found for scope $scope")
            val requestOutcome =
                authorized.requestSingle(credentialMetadata, null, bindingKey).getOrThrow()

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
        println(
            "--> Got a deferred issuance response from server with transaction_id ${deferred.transactionId.value}. Retrying issuance...",
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
        credentialMetadata: CredentialMetadata,
    ): String {
        with(issuer) {
            val requestOutcome =
                noProofRequiredState.requestSingle(credentialMetadata, null).getOrThrow()

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
                        credentialMetadata,
                    )
                }

                is SubmittedRequest.Failed -> throw requestOutcome.error
            }
        }
    }

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

    private fun String.extractASLoginUrl(): URL {
        val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
        val action = form.attr("action")
        return URL(action)
    }

    companion object {
        fun ofUser(actingUser: ActingUser, bindingKeys: Map<String, BindingKey.Jwk>) =
            Wallet(actingUser, bindingKeys)
    }
}

private fun CredentialMetadata.scope(): String? =
    when (this) {
        is MsoMdoc.Model.CredentialMetadata -> scope
        is SdJwtVc.Model.CredentialMetadata -> scope
        is W3CJsonLdDataIntegrity.Model.CredentialMetadata -> scope
        is W3CJsonLdSignedJwt.Model.CredentialMetadata -> scope
        is W3CSignedJwt.Model.CredentialMetadata -> scope
        is CredentialMetadata.ByScope -> scope.value
    }

object KeyGenerator {

    fun randomRSASigningKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun randomECSigningKey(curve: Curve): ECKey = ECKeyGenerator(curve)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()
}
