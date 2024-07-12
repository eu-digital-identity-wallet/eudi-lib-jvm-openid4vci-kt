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
import kotlin.test.assertIs

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
        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CREDENTIAL_OFFER_NO_GRANTS,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            )

        val requests = reqs()
        val (_, outcome) = with(issuer) {
            authorizedRequest.requestBatch(requests).getOrThrow()
        }

        assertIs<SubmissionOutcome.Success>(outcome)
        outcome.credentials.forEach { assertIs<IssuedCredential.Issued>(it) }
    }
}

fun reqs() = listOf(
    IssuanceRequestPayload.ConfigurationBased(
        CredentialConfigurationIdentifier(PID_MsoMdoc),
        MsoMdocClaimSet(
            claims = listOf(
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "family_name",
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "birth_date",
            ),
        ),
    ),
    IssuanceRequestPayload.ConfigurationBased(
        CredentialConfigurationIdentifier(PID_SdJwtVC),
        GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "birth_date",
            ),
        ),
    ),

    IssuanceRequestPayload.ConfigurationBased(
        CredentialConfigurationIdentifier(DEGREE_JwtVcJson),
        GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "degree",
            ),
        ),
    ),

).map { it to CryptoGenerator.rsaProofSigner() }
