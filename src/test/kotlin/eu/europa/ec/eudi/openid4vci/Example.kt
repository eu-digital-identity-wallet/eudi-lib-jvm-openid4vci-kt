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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL
import java.util.*

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

val config = OpenId4VCIConfig(
    clientId = "wallet-dev",
    authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
)

fun main(): Unit = runTest {
    val bindingKey = BindingKey.Jwk(
        algorithm = JWSAlgorithm.RS256,
        jwk = KeyGenerator.randomRSASigningKey(2048),
    )
    val responseEncryptionKey = KeyGenerator.randomRSAEncryptionKey(2048)

    val user = ActingUser("babis", "babis")
    val wallet = Wallet.ofUser(user, bindingKey, responseEncryptionKey)

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
    println("[[Scenario: No offer passed, wallet initiates issuance by credential scopes]]")

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
    val responseEncryptionKey: RSAKey,
) {

    suspend fun issueByScope(scope: String): String {
        val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
        val issuerMetadata =
            CredentialIssuerMetadataResolver.ktor()
                .resolve(credentialIssuerIdentifier).getOrThrow()

        val authServerMetadata =
            AuthorizationServerMetadataResolver.ktor()
                .resolve(issuerMetadata.authorizationServer).getOrThrow()

        val issuer = Issuer.ktor(
            authServerMetadata,
            issuerMetadata,
            config,
        )

        val credentialMetadata = CredentialMetadata.ByScope(Scope.of(scope))

        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            listOf(credentialMetadata),
            authServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        val issuanceResponseEncryption = IssuanceResponseEncryption(
            jwk = responseEncryptionKey,
            algorithm = JWEAlgorithm.RSA_OAEP_256,
            encryptionMethod = EncryptionMethod.A128CBC_HS256,
        )

        // Authorize with auth code flow
        val outcome =
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    noProofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        credentialMetadata,
                        issuanceResponseEncryption,
                    )
                }

                is AuthorizedRequest.ProofRequired -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        credentialMetadata,
                        issuanceResponseEncryption,
                    )
                }
            }

        return outcome
    }

    suspend fun issueByCredentialOfferUrl(coUrl: String): String {
        val offer = httpClientFactory().use { client ->
            val credentialOfferRequestResolver = CredentialOfferRequestResolver(
                httpGet = { url -> client.get(url).body<String>() },
            )
            credentialOfferRequestResolver.resolve(coUrl).getOrThrow()
        }

        return issueByCredentialOffer(offer)
    }

    suspend fun issueByCredentialOffer(offer: CredentialOffer): String {
        val issuer = Issuer.ktor(
            offer.authorizationServerMetadata,
            offer.credentialIssuerMetadata,
            config,
        )

        // Authorize with auth code flow
        val authorizedRequest = authorizeRequestWithAuthCodeUseCase(
            issuer,
            offer.credentials,
            offer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI.toString(),
        )

        val issuanceResponseEncryption = IssuanceResponseEncryption(
            jwk = responseEncryptionKey,
            algorithm = JWEAlgorithm.RSA_OAEP_256,
            encryptionMethod = EncryptionMethod.A128CBC_HS256,
        )

        val outcome =
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    noProofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        offer.credentials[0],
                        issuanceResponseEncryption,
                    )
                }

                is AuthorizedRequest.ProofRequired -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        authorizedRequest,
                        offer.credentials[0],
                        issuanceResponseEncryption,
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
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()

            println("--> Authorization code exchanged with access token : ${authorizedRequest.token.accessToken}")

            authorizedRequest
        }

    private suspend fun proofRequiredSubmissionUseCase(
        issuer: Issuer,
        authorized: AuthorizedRequest.ProofRequired,
        credentialMetadata: CredentialMetadata,
        issuanceResponseEncryption: IssuanceResponseEncryption?,
    ): String {
        with(issuer) {
            val requestOutcome =
                authorized.requestSingle(credentialMetadata, null, bindingKey, issuanceResponseEncryption).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val result = requestOutcome.response.credentialResponses.get(0)
                    when (result) {
                        is CredentialIssuanceResponse.Result.Issued -> result.credential
                        is CredentialIssuanceResponse.Result.Deferred -> result.transactionId
                    }
                }

                is SubmittedRequest.Failed -> throw requestOutcome.error

                is SubmittedRequest.InvalidProof ->
                    throw IllegalStateException("Although providing a proof with c_nonce the proof is still invalid")
            }
        }
    }

    private suspend fun noProofRequiredSubmissionUseCase(
        issuer: Issuer,
        noProofRequiredState: AuthorizedRequest.NoProofRequired,
        credentialMetadata: CredentialMetadata,
        issuanceResponseEncryption: IssuanceResponseEncryption?,
    ): String {
        with(issuer) {
            val requestOutcome =
                noProofRequiredState.requestSingle(credentialMetadata, null, issuanceResponseEncryption).getOrThrow()

            return when (requestOutcome) {
                is SubmittedRequest.Success -> {
                    val result = requestOutcome.response.credentialResponses[0]
                    when (result) {
                        is CredentialIssuanceResponse.Result.Issued -> result.credential
                        is CredentialIssuanceResponse.Result.Deferred -> result.transactionId
                    }
                }

                is SubmittedRequest.InvalidProof -> {
                    proofRequiredSubmissionUseCase(
                        issuer,
                        noProofRequiredState.handleInvalidProof(requestOutcome.cNonce),
                        credentialMetadata,
                        issuanceResponseEncryption,
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
        fun ofUser(actingUser: ActingUser, bindingKey: BindingKey.Jwk, responseEncryptionKey: RSAKey) =
            Wallet(actingUser, bindingKey, responseEncryptionKey)
    }
}

object KeyGenerator {

    fun randomRSASigningKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun randomRSAEncryptionKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.ENCRYPTION)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()
}
