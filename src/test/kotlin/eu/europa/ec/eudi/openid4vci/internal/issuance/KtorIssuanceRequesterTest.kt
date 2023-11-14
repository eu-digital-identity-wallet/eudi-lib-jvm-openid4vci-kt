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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class KtorIssuanceRequesterTest {

    val CredentialIssuer_URL = "https://credential-issuer.example.com"

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `successful issuance of credential in vc+sd-jwt format`() {
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    oidcWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker {},
                    tokenPostMocker {},
                    singleIssuanceRequestMocker(
                        responseBuilder = {
                            val textContent = it?.body as TextContent
                            if (textContent.text.contains("\"proof\":")) {
                                respond(
                                    content =
                                        """
                                        {
                                          "format": "vc+sd-jwt",
                                          "credential": "credential",
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
                                respond(
                                    content =
                                        """
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
                        },
                    ) {
                    },
                ),
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val sdJwtVcPid = CredentialMetadata.ByScope(Scope.of("eu.europa.ec.eudiw.pid_vc_sd_jwt"))
            val authorizedRequest = authorizeIssuanceOfWithIssuer(issuer, sdJwtVcPid)

            with(issuer) {
                when (authorizedRequest) {
                    is AuthorizedRequest.NoProofRequired -> {
                        val submittedRequest =
                            authorizedRequest.requestSingle(sdJwtVcPid, null).getOrThrow()
                        when (submittedRequest) {
                            is SubmittedRequest.InvalidProof -> {
                                val proofRequired =
                                    authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                val response = proofRequired.requestSingle(
                                    sdJwtVcPid,
                                    null,
                                    BindingKey.Jwk(
                                        algorithm = JWSAlgorithm.RS256,
                                        jwk = randomRSASigningKey(2048),
                                    ),
                                )
                                org.hamcrest.MatcherAssert.assertThat(
                                    "Second attempt should be successful",
                                    response.getOrThrow() is SubmittedRequest.Success,
                                )
                            }

                            is SubmittedRequest.Failed -> fail(
                                "Failed with error ${submittedRequest.error}",
                            )

                            is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                        }
                    }

                    is AuthorizedRequest.ProofRequired ->
                        fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                }
            }
        }
    }

    @Test
    fun `successful issuance of credential in mso_mdoc format`() {
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    oidcWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker {},
                    tokenPostMocker {},
                    singleIssuanceRequestMocker(
                        responseBuilder = {
                            val textContent = it?.body as TextContent
                            if (textContent.text.contains("\"proof\":")) {
                                respond(
                                    content =
                                        """
                                        {
                                          "format": "mso_mdoc",
                                          "credential": "credential",
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
                                respond(
                                    content =
                                        """
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
                        },
                    ) {},
                ),
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val msoMdocPid = CredentialMetadata.ByScope(Scope.of("eu.europa.ec.eudiw.pid_mso_mdoc"))
            val authorizedRequest = authorizeIssuanceOfWithIssuer(issuer, msoMdocPid)

            with(issuer) {
                when (authorizedRequest) {
                    is AuthorizedRequest.NoProofRequired -> {
                        val submittedRequest =
                            authorizedRequest.requestSingle(msoMdocPid, null).getOrThrow()
                        when (submittedRequest) {
                            is SubmittedRequest.InvalidProof -> {
                                val proofRequired =
                                    authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                val response = proofRequired.requestSingle(
                                    msoMdocPid,
                                    null,
                                    BindingKey.Jwk(
                                        algorithm = JWSAlgorithm.RS256,
                                        jwk = randomRSASigningKey(2048),
                                    ),
                                )
                                org.hamcrest.MatcherAssert.assertThat(
                                    "Second attempt should be successful",
                                    response.getOrThrow() is SubmittedRequest.Success,
                                )
                            }

                            is SubmittedRequest.Failed -> fail(
                                "Failed with error ${submittedRequest.error}",
                            )

                            is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                        }
                    }

                    is AuthorizedRequest.ProofRequired ->
                        fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                }
            }
        }
    }

    @Test
    fun `successful batch issuance`() {
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    oidcWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker {},
                    tokenPostMocker {},
                    batchIssuanceRequestMocker(
                        responseBuilder = {
                            val textContent = it?.body as TextContent
                            if (textContent.text.contains("\"proof\":")) {
                                respond(
                                    content = Json.encodeToString(
                                        BatchIssuanceSuccessResponse(
                                            credentialResponses = listOf(
                                                BatchIssuanceSuccessResponse.CertificateIssuanceResponse(
                                                    format = MsoMdocFormat.FORMAT,
                                                    credential = "issued_credential_content_mso_mdoc",
                                                ),
                                                BatchIssuanceSuccessResponse.CertificateIssuanceResponse(
                                                    format = SdJwtVcFormat.FORMAT,
                                                    credential = "issued_credential_content_sd_jwt_vc",
                                                ),
                                            ),
                                            cNonce = "wlbQc6pCJp",
                                            cNonceExpiresInSeconds = 86400,
                                        ),
                                    ),
                                    status = HttpStatusCode.OK,
                                    headers = headersOf(
                                        HttpHeaders.ContentType to listOf("application/json"),
                                    ),
                                )
                            } else {
                                respond(
                                    content =
                                        """
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
                        },
                    ) {},
                ),
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val msoMdocPid = CredentialMetadata.ByScope(Scope.of("eu.europa.ec.eudiw.pid_mso_mdoc"))
            val authorizedRequest = authorizeIssuanceOfWithIssuer(issuer, msoMdocPid)
            val bindingKey = BindingKey.Jwk(
                algorithm = JWSAlgorithm.RS256,
                jwk = randomRSASigningKey(2048),
            )
            with(issuer) {
                when (authorizedRequest) {
                    is AuthorizedRequest.NoProofRequired -> {
                        val credentialMetadata = listOf(
                            CredentialMetadata.ByScope(Scope.of(PID_MsoMdoc_SCOPE)) to null,
                            CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE)) to null,
                        )
                        val submittedRequest = authorizedRequest.requestBatch(credentialMetadata).getOrThrow()

                        when (submittedRequest) {
                            is SubmittedRequest.InvalidProof -> {
                                val proofRequired = authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                val credentialMetadataTriples = listOf(
                                    Triple(CredentialMetadata.ByScope(Scope.of(PID_MsoMdoc_SCOPE)), null, bindingKey),
                                    Triple(CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE)), null, bindingKey),
                                )

                                val response = proofRequired.requestBatch(credentialMetadataTriples).getOrThrow()

                                assertTrue("Second attempt should be successful") {
                                    response is SubmittedRequest.Success
                                }

                                assertTrue("Second attempt should be successful") {
                                    (response as SubmittedRequest.Success).response.credentialResponses.all {
                                        it is CredentialIssuanceResponse.Result.Issued &&
                                            it.format in listOf(MsoMdocFormat.FORMAT, SdJwtVcFormat.FORMAT)
                                    }
                                }
                            }

                            is SubmittedRequest.Failed -> fail(
                                "Failed with error ${submittedRequest.error}",
                            )

                            is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                        }
                    }

                    is AuthorizedRequest.ProofRequired ->
                        fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                }
            }
        }
    }

    private suspend fun issuer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialIssuerIdentifier: CredentialIssuerId,
    ): Issuer {
        val issuerMetadata =
            CredentialIssuerMetadataResolver.ktor(
                ktorHttpClientFactory = ktorHttpClientFactory,
            ).resolve(credentialIssuerIdentifier).getOrThrow()

        val authServerMetadata =
            AuthorizationServerMetadataResolver.ktor(
                ktorHttpClientFactory = ktorHttpClientFactory,
            ).resolve(issuerMetadata.authorizationServer).getOrThrow()

        val issuer = Issuer.make(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authServerMetadata,
                ktorHttpClientFactory = ktorHttpClientFactory,
                config = vciWalletConfiguration,
            ),
            IssuanceRequester.ktor(
                issuerMetadata = issuerMetadata,
                ktorHttpClientFactory = ktorHttpClientFactory,
            ),
        )
        return issuer
    }

    private suspend fun authorizeIssuanceOfWithIssuer(
        issuer: Issuer,
        vararg credentials: CredentialMetadata,
    ): AuthorizedRequest {
        with(issuer) {
            val parRequested = pushAuthorizationCodeRequest(credentials.asList(), null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            return parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
    }

    private fun randomRSASigningKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()
}
