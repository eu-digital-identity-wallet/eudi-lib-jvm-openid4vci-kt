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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.days
import kotlin.time.toJavaDuration

class CredentialIssuerMetadataJsonParserTest {

    @Test
    fun `parsing valid preferred_key_storage_status_period succeeds`() {
        val json = getResourceAsText("well-known/openid-credential-issuer_attestation_proof_supported.json")
        val credentialIssuerMetadata = CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)

        val credentialConfiguration =
            assertNotNull(
                credentialIssuerMetadata.credentialConfigurationsSupported[
                    CredentialConfigurationIdentifier(
                        "eu.europa.ec.eudiw.pid_vc_sd_jwt",
                    ),
                ],
            )

        val jwtProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.JWT])
        check(jwtProof is ProofTypeMeta.Jwt)
        assertEquals(1.days.toJavaDuration(), jwtProof.keyAttestationConstraints.preferredKeyStorageStatusPeriod?.value)

        val attestationProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.ATTESTATION])
        check(attestationProof is ProofTypeMeta.Attestation)
        assertEquals(1.days.toJavaDuration(), attestationProof.keyAttestationConstraints.preferredKeyStorageStatusPeriod?.value)
    }

    @Test
    fun `trying to parse negative preferred_key_storage_status_period fails`() {
        val json = getResourceAsText("well-known/openid-credential-issuer_invalid_attestation_proof_supported.json")
        val exception = assertFailsWith<CredentialIssuerMetadataValidationError.InvalidCredentialsSupported> {
            CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)
        }
        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("Duration must be positive", cause.message)
    }

    @Test
    fun `fails when jwt proof does not require key attestation`() {
        val json = getResourceAsText("well-known/openid-credential-issuer_jwt_proof_no_keyattestation.json")
        val exception = assertFailsWith<CredentialIssuerMetadataValidationError.InvalidCredentialsSupported> {
            CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)
        }
        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("jwt proof must contain 'key_attestations_required'", cause.message)
    }
}
