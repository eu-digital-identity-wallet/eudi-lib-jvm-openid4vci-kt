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
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.proofsSpecForEcKeys
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialResponseSuccessTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.*

class IssuanceBatchRequestTest {

    @Test
    fun `successful batch issuance`() = runTest {
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_REQUIRED),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    if (textContent.text.contains("\"proofs\":")) {
                        encryptedResponseDataBuilder(it) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", JsonPrimitive("issued_credential_content_mso_mdoc0"))
                                        },
                                        buildJsonObject {
                                            put("credential", JsonPrimitive("issued_credential_content_mso_mdoc1"))
                                        },
                                        buildJsonObject {
                                            put("credential", JsonPrimitive("issued_credential_content_mso_mdoc2"))
                                        },
                                    ),
                                ),
                            )
                        }
                    } else {
                        respond(
                            content = """
                            {
                                "error": "invalid_proof",
                            } 
                            """.trimIndent(),
                            status = HttpStatusCode.BadRequest,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    }
                },
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequestTO.proofs,
                        "Multiple proofs expected but received one proof",
                    )
                    val jwtProofs = issuanceRequestTO.proofs.jwtProofs
                    assertNotNull(jwtProofs, "Jwt Proofs expected")
                    val distinctNonces = jwtProofs
                        .map { SignedJWT.parse(it) }
                        .map { it.jwtClaimsSet.getStringClaim("nonce") }
                        .distinct()

                    assertTrue("In the context of an issuance request all proofs must contain the same nonce, but they don't") {
                        distinctNonces.size == 1
                    }
                },
            ),
        )
        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

        val request = IssuanceRequestPayload.ConfigurationBased(
            CredentialConfigurationIdentifier(PID_MsoMdoc),
        )
        val (_, outcome) = with(issuer) {
            authorizedRequest.request(request, proofsSpecForEcKeys(Curve.P_256, 3)).getOrThrow()
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
