/*
 * Copyright (c) 2023-2026 European Commission
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

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.jwtProofSpec
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialResponseSuccessTO
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.*

class IssuanceBatchRequestTest {

    @Test
    fun `successful batch issuance`() = runTest {
        val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_REQUIRED
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
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
                },
                requestValidator = { request ->
                    encryptionAwareRequestValidator<CredentialRequestTO>(request, issuerMetadataVersion) {
                        assertNotNull(
                            it.proofs,
                            "Proofs expected but received none",
                        )
                        val jwtProofs = it.proofs.jwtProofs
                        assertNotNull(jwtProofs, "Jwt Proofs expected")
                        assertEquals(1, jwtProofs.size, "Exactly one Jwt Proof expected")
                        val keyAttestation =
                            KeyAttestationJWT(SignedJWT.parse(jwtProofs.first()).header.getCustomParam("attestation") as String)
                        assertEquals(3, keyAttestation.attestedKeys.size, "Exactly three attested keys expected")
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
            authorizedRequest.request(request, jwtProofSpec(attestedKeysCount = 3)).getOrThrow()
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
