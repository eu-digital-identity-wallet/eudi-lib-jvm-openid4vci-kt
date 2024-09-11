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

import eu.europa.ec.eudi.openid4vci.internal.http.CredentialResponseSuccessTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.fail

class IssuanceBatchRequestTest {

    @Test
    fun `successful batch issuance`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(encryptedResponses = EncryptedResponses.REQUIRED),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    if (textContent.text.contains("\"proofs\":")) {
                        encryptedResponseDataBuilder(it) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        "issued_credential_content_mso_mdoc0",
                                        "issued_credential_content_mso_mdoc1",
                                        "issued_credential_content_mso_mdoc2",
                                    ),
                                    cNonce = "wlbQc6pCJp",
                                    cNonceExpiresInSeconds = 86400,
                                ),
                            )
                        }
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

        val (request, popSigners) = reqs()
        val (_, outcome) = with(issuer) {
            authorizedRequest.request(request, popSigners).getOrThrow()
        }
        when (outcome) {
            is SubmissionOutcome.Failed -> {
                fail(outcome.error.message)
            }
            is SubmissionOutcome.Deferred -> {
                fail("Got deferred")
            }
            is SubmissionOutcome.Success -> {
                outcome.credentials.forEach { assertIs<IssuedCredential>(it) }
            }
        }
    }
}

fun reqs() =
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
    ) to (0..2).map { CryptoGenerator.rsaProofSigner() }
