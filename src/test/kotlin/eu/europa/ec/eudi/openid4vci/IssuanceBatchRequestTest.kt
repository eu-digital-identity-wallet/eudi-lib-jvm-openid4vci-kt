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

import eu.europa.ec.eudi.openid4vci.internal.http.BatchCredentialResponseSuccessTO
import eu.europa.ec.eudi.openid4vci.internal.http.IssuanceResponseTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceBatchRequestTest {

    @Test
    fun `successful batch issuance`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            batchIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    if (textContent.text.contains("\"proof\":")) {
                        respond(
                            content = Json.encodeToString(
                                BatchCredentialResponseSuccessTO(
                                    credentialResponses = listOf(
                                        IssuanceResponseTO(
                                            credential = "issued_credential_content_mso_mdoc",
                                        ),
                                        IssuanceResponseTO(
                                            credential = "issued_credential_content_sd_jwt_vc",
                                        ),
                                        IssuanceResponseTO(
                                            credential = "issued_credential_content_jwt_vc_json",
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
                },
            ) {},
        )
        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(mockedKtorHttpClientFactory, CREDENTIAL_OFFER_NO_GRANTS)

        val claimSet_mso_mdoc = MsoMdocClaimSet(
            claims = listOf(
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "family_name",
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "birth_date",

            ),
        )
        val claimSet_sd_jwt_vc = GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "birth_date",
            ),
        )

        val claimSet_w3c_signed_jwt = GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "degree",
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val batchRequestPayload = listOf(
                        IssuanceRequestPayload.ConfigurationBased(
                            CredentialConfigurationIdentifier(PID_MsoMdoc),
                            claimSet_mso_mdoc,
                        ),
                        IssuanceRequestPayload.ConfigurationBased(
                            CredentialConfigurationIdentifier(PID_SdJwtVC),
                            claimSet_sd_jwt_vc,
                        ),
                        IssuanceRequestPayload.ConfigurationBased(
                            CredentialConfigurationIdentifier(DEGREE_JwtVcJson),
                            claimSet_w3c_signed_jwt,
                        ),
                    )
                    val submittedRequest = authorizedRequest.requestBatch(batchRequestPayload).getOrThrow()
                    when (submittedRequest) {
                        is SubmissionOutcome.InvalidProof -> {
                            val proofRequired = authorizedRequest.withCNonce(submittedRequest.cNonce)

                            val proofSigner = CryptoGenerator.rsaProofSigner()
                            val credentialMetadataTriples = listOf(
                                Pair(
                                    IssuanceRequestPayload.ConfigurationBased(
                                        CredentialConfigurationIdentifier(PID_MsoMdoc),
                                        claimSet_mso_mdoc,
                                    ),
                                    proofSigner,
                                ),
                                Pair(
                                    IssuanceRequestPayload.ConfigurationBased(
                                        CredentialConfigurationIdentifier(PID_SdJwtVC),
                                        claimSet_sd_jwt_vc,
                                    ),
                                    proofSigner,
                                ),
                                Pair(
                                    IssuanceRequestPayload.ConfigurationBased(
                                        CredentialConfigurationIdentifier(DEGREE_JwtVcJson),
                                        claimSet_w3c_signed_jwt,
                                    ),
                                    proofSigner,
                                ),
                            )

                            val response = proofRequired.requestBatch(credentialMetadataTriples).getOrThrow()

                            assertTrue("Second attempt should be successful") {
                                response is SubmissionOutcome.Success
                            }

                            assertTrue("Second attempt should be successful") {
                                (response as SubmissionOutcome.Success).credentials.all {
                                    it is IssuedCredential.Issued
                                }
                            }
                        }

                        is SubmissionOutcome.Failed -> fail(
                            "Failed with error ${submittedRequest.error}",
                        )

                        is SubmissionOutcome.Success -> fail(
                            "first attempt should be unsuccessful",
                        )
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }
}
