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
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceDeferredRequestTest {

    val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["$PID_SdJwtVC_SCOPE"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `when issuer responds with invalid_transaction_id, response should be of type Errored`() {
        issuanceTestBed(
            { client ->
                val (_, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt)

                val bindingKey = BindingKey.Jwk(
                    algorithm = JWSAlgorithm.RS256,
                    jwk = KeyGenerator.randomRSASigningKey(2048),
                )

                with(issuer) {
                    when (authorizedRequest) {
                        is AuthorizedRequest.NoProofRequired -> {
                            val credentialMetadata = CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE))
                            val submittedRequest =
                                authorizedRequest.requestSingle(credentialMetadata, null).getOrThrow()
                            when (submittedRequest) {
                                is SubmittedRequest.InvalidProof -> {
                                    val proofRequired =
                                        authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                    val secondSubmittedRequest =
                                        proofRequired.requestSingle(credentialMetadata, null, bindingKey).getOrThrow()

                                    val transactionId = when (secondSubmittedRequest) {
                                        is SubmittedRequest.Success -> {
                                            val result = secondSubmittedRequest.response.credentialResponses[0]
                                            (result as CredentialIssuanceResponse.Result.Deferred).transactionId
                                        }

                                        else -> fail("Success response expected but was not")
                                    }

                                    val requestDeferredIssuance =
                                        authorizedRequest.requestDeferredIssuance(TransactionId(transactionId))
                                            .getOrThrow()

                                    assertTrue("Expected response type Errored but was not") {
                                        requestDeferredIssuance is DeferredCredentialIssuanceResponse.Errored
                                    }

                                    assertTrue("Expected interval but was not present") {
                                        (requestDeferredIssuance as DeferredCredentialIssuanceResponse.Errored)
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
            },
            { call ->
                val bodyStr = call.receive<String>()

                val issuanceRequest = asIssuanceRequest(bodyStr)
                val deferredIssuanceRequest = asDeferredIssuanceRequest(bodyStr)
                if (issuanceRequest != null) {
                    println(issuanceRequest)
                    respondToCredentialIssuanceRequest(issuanceRequest, call)
                } else if (deferredIssuanceRequest != null) {
                    println(deferredIssuanceRequest)
                    respondToDeferredIssuanceRequest(call, true, false)
                } else {
                    call.respondText(
                        """
                            {
                              "error": "invalid_request"                              
                            }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    @Test
    fun `when issuer responds with issuance_pending, response should be of type IssuancePending`() {
        issuanceTestBed(
            { client ->
                val (_, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt)

                val bindingKey = BindingKey.Jwk(
                    algorithm = JWSAlgorithm.RS256,
                    jwk = KeyGenerator.randomRSASigningKey(2048),
                )

                with(issuer) {
                    when (authorizedRequest) {
                        is AuthorizedRequest.NoProofRequired -> {
                            val credentialMetadata = CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE))
                            val submittedRequest =
                                authorizedRequest.requestSingle(credentialMetadata, null).getOrThrow()
                            when (submittedRequest) {
                                is SubmittedRequest.InvalidProof -> {
                                    val proofRequired =
                                        authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                    val secondSubmittedRequest =
                                        proofRequired.requestSingle(credentialMetadata, null, bindingKey).getOrThrow()

                                    val transactionId = when (secondSubmittedRequest) {
                                        is SubmittedRequest.Success -> {
                                            val result = secondSubmittedRequest.response.credentialResponses[0]
                                            (result as CredentialIssuanceResponse.Result.Deferred).transactionId
                                        }

                                        else -> fail("Success response expected but was not")
                                    }

                                    val requestDeferredIssuance =
                                        authorizedRequest.requestDeferredIssuance(TransactionId(transactionId))
                                            .getOrThrow()

                                    assertTrue("Expected response type IssuancePending but was not") {
                                        requestDeferredIssuance is DeferredCredentialIssuanceResponse.IssuancePending
                                    }

                                    assertTrue("Expected interval but was not present") {
                                        (requestDeferredIssuance as DeferredCredentialIssuanceResponse.IssuancePending)
                                            .transactionId.interval != null
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
            },
            { call ->
                val bodyStr = call.receive<String>()

                val issuanceRequest = asIssuanceRequest(bodyStr)
                val deferredIssuanceRequest = asDeferredIssuanceRequest(bodyStr)
                if (issuanceRequest != null) {
                    println(issuanceRequest)
                    respondToCredentialIssuanceRequest(issuanceRequest, call)
                } else if (deferredIssuanceRequest != null) {
                    println(deferredIssuanceRequest)
                    respondToDeferredIssuanceRequest(call, false)
                } else {
                    call.respondText(
                        """
                            {
                              "error": "invalid_request"                              
                            }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    @Test
    fun `when deferred request is valid, credential must be issued`() {
        issuanceTestBed(
            { client ->

                val (_, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt)

                val bindingKey = BindingKey.Jwk(
                    algorithm = JWSAlgorithm.RS256,
                    jwk = KeyGenerator.randomRSASigningKey(2048),
                )

                with(issuer) {
                    when (authorizedRequest) {
                        is AuthorizedRequest.NoProofRequired -> {
                            val credentialMetadata = CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE))
                            val submittedRequest =
                                authorizedRequest.requestSingle(credentialMetadata, null).getOrThrow()
                            when (submittedRequest) {
                                is SubmittedRequest.InvalidProof -> {
                                    val proofRequired =
                                        authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                    val secondSubmittedRequest =
                                        proofRequired.requestSingle(credentialMetadata, null, bindingKey).getOrThrow()

                                    val transactionId = when (secondSubmittedRequest) {
                                        is SubmittedRequest.Success -> {
                                            val result = secondSubmittedRequest.response.credentialResponses[0]
                                            (result as CredentialIssuanceResponse.Result.Deferred).transactionId
                                        }

                                        else -> fail("Success response expected but was not")
                                    }

                                    val requestDeferredIssuance =
                                        authorizedRequest.requestDeferredIssuance(TransactionId(transactionId))
                                            .getOrThrow()

                                    assertTrue("Expected response type Issued but was not") {
                                        requestDeferredIssuance is DeferredCredentialIssuanceResponse.Issued
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
            },
            { call ->
                val bodyStr = call.receive<String>()

                val issuanceRequest = asIssuanceRequest(bodyStr)
                val deferredIssuanceRequest = asDeferredIssuanceRequest(bodyStr)
                if (issuanceRequest != null) {
                    println(issuanceRequest)
                    respondToCredentialIssuanceRequest(issuanceRequest, call)
                } else if (deferredIssuanceRequest != null) {
                    println(deferredIssuanceRequest)
                    respondToDeferredIssuanceRequest(call, true)
                } else {
                    call.respondText(
                        """
                            {
                              "error": "invalid_request"                              
                            }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    private suspend fun respondToDeferredIssuanceRequest(
        call: ApplicationCall,
        credentialIsReady: Boolean,
        transactionIdIsValid: Boolean = true,
    ) {
        if (credentialIsReady && transactionIdIsValid) {
            call.respondText(
                """
                    {
                      "format": "vc+sd-jwt",
                      "credential": "credential_content"
                    }
                """.trimIndent(),
                ContentType.parse("application/json"),
                HttpStatusCode.OK,
            )
        } else {
            val error =
                if (!transactionIdIsValid) {
                    "invalid_transaction_id "
                } else {
                    "issuance_pending"
                }

            call.respondText(
                """
                {
                  "error": "$error",
                  "interval": 5
                }
                """.trimIndent(),
                ContentType.parse("application/json"),
                HttpStatusCode.BadRequest,
            )
        }
    }

    private suspend fun respondToCredentialIssuanceRequest(
        issuanceRequest: SdJwtVcFormat.CredentialIssuanceRequestTO,
        call: ApplicationCall,
    ) {
        if (issuanceRequest.proof != null) {
            call.respondText(
                """
                    {
                      "format": "vc+sd-jwt",
                      "transaction_id": "1234565768122",
                      "c_nonce": "wlbQc6pCJp",
                      "c_nonce_expires_in": 86400
                    }
                """.trimIndent(),
                ContentType.parse("application/json"),
                HttpStatusCode.OK,
            )
        } else {
            call.respondText(
                """
                    {
                        "error": "invalid_proof",
                        "c_nonce": "ERE%@^TGWYEYWEY",
                        "c_nonce_expires_in": 34
                    } 
                """.trimIndent(),
                ContentType.parse("application/json"),
                HttpStatusCode.BadRequest,
            )
        }
    }

    private fun asDeferredIssuanceRequest(bodyStr: String): DeferredIssuanceRequestTO? =
        try {
            Json.decodeFromString<DeferredIssuanceRequestTO>(bodyStr)
        } catch (ex: Exception) {
            null
        }

    private fun asIssuanceRequest(bodyStr: String): SdJwtVcFormat.CredentialIssuanceRequestTO? =
        try {
            Json.decodeFromString<CredentialIssuanceRequestTO>(bodyStr) as SdJwtVcFormat.CredentialIssuanceRequestTO
        } catch (ex: Exception) {
            null
        }

    private suspend fun authorizeRequestForCredentialOffer(
        client: HttpClient,
        credentialOfferStr: String,
    ): Triple<CredentialOffer, AuthorizedRequest, Issuer> {
        val offer = CredentialOfferRequestResolver(
            httpGet = createGetASMetadata(client),
        ).resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()

        val issuer = Issuer.make(
            IssuanceAuthorizer.make(
                offer.authorizationServerMetadata,
                vciWalletConfiguration,
                createPostPar(client),
                createGetAccessToken(client),
            ),
            IssuanceRequester.make(
                issuerMetadata = offer.credentialIssuerMetadata,
                postIssueRequest = createPostIssuance(client),
                postDeferredIssueRequest = createPostDeferredIssuance(client),
            ),
        )

        val authorizedRequest = with(issuer) {
            val parRequested = issuer.pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
        return Triple(offer, authorizedRequest, issuer)
    }
}
