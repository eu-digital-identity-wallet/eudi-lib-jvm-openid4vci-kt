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
import eu.europa.ec.eudi.openid4vci.internal.DeferredIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.formats.SdJwtVcIssuanceRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.*

class IssuanceDeferredRequestTest {

    val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"

    val PID_SdJwtVC = "eu.europa.ec.eudiw.pid_vc_sd_jwt"

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    )

    @Test
    fun `when issuer responds with invalid_transaction_id, response should be of type Errored`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    val issuanceRequest = asIssuanceRequest(textContent.text)
                    respondToCredentialIssuanceRequest(this, issuanceRequest)
                },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = {
                    respondToDeferredIssuanceRequest(this, credentialIsReady = true, transactionIdIsValid = false)
                },
            ),
        )
        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt,
            )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = CredentialConfigurationIdentifier(PID_SdJwtVC) to null
                    val submittedRequest =
                        authorizedRequest.requestSingle(credentialConfigurationId, null).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired =
                                authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val secondSubmittedRequest =
                                proofRequired.requestSingle(credentialConfigurationId, null, CryptoGenerator.rsaProofSigner()).getOrThrow()

                            val deferred = when (secondSubmittedRequest) {
                                is SubmittedRequest.Success -> {
                                    val issuedCredential = secondSubmittedRequest.credentials[0]
                                    require(issuedCredential is IssuedCredential.Deferred)
                                    issuedCredential
                                }

                                else -> fail("Success response expected but was not")
                            }

                            val requestDeferredIssuance =
                                authorizedRequest.queryForDeferredCredential(deferred)
                                    .getOrThrow()

                            assertTrue("Expected response type Errored but was not") {
                                requestDeferredIssuance is DeferredCredentialQueryOutcome.Errored
                            }

                            assertTrue("Expected interval but was not present") {
                                (requestDeferredIssuance as DeferredCredentialQueryOutcome.Errored)
                                    .error != "invalid_transaction_id"
                            }
                        }

                        is SubmittedRequest.Failed -> fail("Failed with error ${submittedRequest.error}")
                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when issuer responds with issuance_pending, response should be of type IssuancePending`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    val issuanceRequest = asIssuanceRequest(textContent.text)
                    respondToCredentialIssuanceRequest(this, issuanceRequest)
                },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = {
                    respondToDeferredIssuanceRequest(this, false)
                },
            ),
        )

        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt,
            )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = CredentialConfigurationIdentifier(PID_SdJwtVC)
                    val requestCredentialIdentifier = credentialConfigurationId to null
                    val submittedRequest =
                        authorizedRequest.requestSingle(requestCredentialIdentifier, null).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired =
                                authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val secondSubmittedRequest =
                                proofRequired.requestSingle(
                                    requestCredentialIdentifier,
                                    null,
                                    CryptoGenerator.rsaProofSigner(),
                                ).getOrThrow()

                            val deferred = when (secondSubmittedRequest) {
                                is SubmittedRequest.Success -> {
                                    val issuedCredential = secondSubmittedRequest.credentials[0]
                                    require(issuedCredential is IssuedCredential.Deferred)
                                    issuedCredential
                                }

                                else -> fail("Success response expected but was not")
                            }

                            val requestDeferredIssuance =
                                authorizedRequest.queryForDeferredCredential(deferred)
                                    .getOrThrow()

                            assertIs<DeferredCredentialQueryOutcome.IssuancePending>(requestDeferredIssuance)
                            assertNotNull(requestDeferredIssuance.interval) { "Expected interval but was not present" }
                        }

                        is SubmittedRequest.Failed -> fail("Failed with error ${submittedRequest.error}")
                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when deferred request is valid, credential must be issued`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    val issuanceRequest = asIssuanceRequest(textContent.text)
                    respondToCredentialIssuanceRequest(this, issuanceRequest)
                },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = {
                    respondToDeferredIssuanceRequest(this, true)
                },
                requestValidator = {
                    assertTrue("No Authorization header passed.") {
                        it.headers.contains("Authorization")
                    }

                    assertTrue("Authorization header malformed.") {
                        it.headers["Authorization"]?.contains("Bearer") ?: false
                    }
                    assertTrue("Content Type must be application/json") {
                        it.body.contentType == ContentType.parse("application/json")
                    }
                    val textContent = it.body as TextContent
                    val deferredIssuanceRequest = asDeferredIssuanceRequest(textContent.text)
                    deferredIssuanceRequest?.let {
                        assertTrue("No transaction id passed") {
                            deferredIssuanceRequest.transactionId.isNotBlank()
                        }
                    }
                },
            ),
        )

        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt,
            )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = CredentialConfigurationIdentifier(PID_SdJwtVC)
                    val requestCredentialIdentifier = credentialConfigurationId to null
                    val submittedRequest =
                        authorizedRequest.requestSingle(requestCredentialIdentifier, null).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired =
                                authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val secondSubmittedRequest =
                                proofRequired.requestSingle(
                                    requestCredentialIdentifier,
                                    null,
                                    CryptoGenerator.rsaProofSigner(),
                                ).getOrThrow()

                            val deferred = when (secondSubmittedRequest) {
                                is SubmittedRequest.Success -> {
                                    val issuedCredential = secondSubmittedRequest.credentials[0]
                                    require(issuedCredential is IssuedCredential.Deferred)
                                    issuedCredential
                                }

                                else -> fail("Success response expected but was not")
                            }

                            val requestDeferredIssuance = authorizedRequest.queryForDeferredCredential(deferred)
                                .getOrThrow()
                            assertIs<DeferredCredentialQueryOutcome.Issued>(requestDeferredIssuance)
                        }

                        is SubmittedRequest.Failed -> fail("Failed with error ${submittedRequest.error}")
                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    private fun respondToDeferredIssuanceRequest(
        call: MockRequestHandleScope,
        credentialIsReady: Boolean,
        transactionIdIsValid: Boolean = true,
    ): HttpResponseData =
        if (credentialIsReady && transactionIdIsValid) {
            call.respond(
                content = """
                    {
                      "format": "vc+sd-jwt",
                      "credential": "credential_content"
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        } else {
            val error =
                if (!transactionIdIsValid) {
                    "invalid_transaction_id "
                } else {
                    "issuance_pending"
                }

            call.respond(
                content = """
                    {
                      "error": "$error",
                      "interval": 5
                    }
                """.trimIndent(),
                status = HttpStatusCode.BadRequest,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        }

    private fun respondToCredentialIssuanceRequest(
        call: MockRequestHandleScope,
        issuanceRequest: SdJwtVcIssuanceRequestTO?,
    ): HttpResponseData =
        if (issuanceRequest == null) {
            call.respond(
                content = """
                                {
                                  "error": "invalid_request"                              
                                }
                """.trimIndent(),
                status = HttpStatusCode.BadRequest,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        } else if (issuanceRequest.proof != null) {
            call.respond(
                content = """
                    {
                      "format": "vc+sd-jwt",
                      "transaction_id": "1234565768122",
                      "c_nonce": "wlbQc6pCJp",
                      "c_nonce_expires_in": 86400
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        } else {
            call.respond(
                content = """
                    {
                        "error": "invalid_proof",
                        "c_nonce": "ERE%@^TGWYEYWEY",
                        "c_nonce_expires_in": 34
                    } 
                """.trimIndent(),
                status = HttpStatusCode.BadRequest,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        }

    private fun asDeferredIssuanceRequest(bodyStr: String): DeferredIssuanceRequestTO? =
        try {
            Json.decodeFromString<DeferredIssuanceRequestTO>(bodyStr)
        } catch (ex: Exception) {
            null
        }

    private fun asIssuanceRequest(bodyStr: String): SdJwtVcIssuanceRequestTO? =
        try {
            Json.decodeFromString<CredentialIssuanceRequestTO>(bodyStr) as SdJwtVcIssuanceRequestTO
        } catch (ex: Exception) {
            null
        }

    private suspend fun authorizeRequestForCredentialOffer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialOfferStr: String,
    ): Triple<CredentialOffer, AuthorizedRequest, Issuer> {
        val offer = CredentialOfferRequestResolver(ktorHttpClientFactory = ktorHttpClientFactory)
            .resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()

        val issuer = Issuer.make(
            config = vciWalletConfiguration,
            credentialOffer = offer,
            ktorHttpClientFactory = ktorHttpClientFactory,
        )

        val authorizedRequest = with(issuer) {
            val parRequested = prepareAuthorizationRequest().getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested.authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode)).getOrThrow()
        }
        return Triple(offer, authorizedRequest, issuer)
    }
}
