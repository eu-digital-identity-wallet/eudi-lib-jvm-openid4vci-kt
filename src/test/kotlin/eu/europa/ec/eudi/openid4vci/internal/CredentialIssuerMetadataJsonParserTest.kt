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
import kotlin.test.assertNull
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
        assertEquals(1.days.toJavaDuration(), jwtProof.keyAttestationRequirement?.preferredKeyStorageStatusPeriod?.value)

        val attestationProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.ATTESTATION])
        check(attestationProof is ProofTypeMeta.Attestation)
        assertEquals(1.days.toJavaDuration(), attestationProof.keyAttestationRequirement?.preferredKeyStorageStatusPeriod?.value)
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
    fun `absent key_attestations_required is parsed as no key attestation requirement`() {
        // 'key_attestations_required' is OPTIONAL in OpenID4VCI; when it is absent the issuer does
        // not require a key attestation, so the parsed requirement is null.
        val json = getResourceAsText("well-known/openid-credential-issuer_absent_key_attestations_required.json")
        val credentialIssuerMetadata = CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)

        val credentialConfiguration =
            assertNotNull(
                credentialIssuerMetadata.credentialConfigurationsSupported[
                    CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                ],
            )

        val jwtProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.JWT])
        check(jwtProof is ProofTypeMeta.Jwt)
        assertNull(jwtProof.keyAttestationRequirement)

        val attestationProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.ATTESTATION])
        check(attestationProof is ProofTypeMeta.Attestation)
        assertNull(attestationProof.keyAttestationRequirement)
    }

    @Test
    fun `empty key_attestations_required is parsed as an unconstrained key attestation requirement`() {
        // An empty 'key_attestations_required' object means a key attestation IS required but
        // without additional constraints, which is distinct from the field being absent.
        val json = getResourceAsText("well-known/openid-credential-issuer_empty_key_attestations_required.json")
        val credentialIssuerMetadata = CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)

        val credentialConfiguration =
            assertNotNull(
                credentialIssuerMetadata.credentialConfigurationsSupported[
                    CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                ],
            )

        val jwtProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.JWT])
        check(jwtProof is ProofTypeMeta.Jwt)
        assertEquals(KeyAttestationRequirement(null, null, null), jwtProof.keyAttestationRequirement)

        val attestationProof = assertNotNull(credentialConfiguration.proofTypesSupported[ProofType.ATTESTATION])
        check(attestationProof is ProofTypeMeta.Attestation)
        assertEquals(KeyAttestationRequirement(null, null, null), attestationProof.keyAttestationRequirement)
    }

    @Test
    fun `fails when credential configuration does not support both jwt proofs and attestation proofs`() {
        fun test(resource: String) {
            val json = getResourceAsText(resource)
            val exception = assertFailsWith<CredentialIssuerMetadataValidationError.InvalidCredentialsSupported> {
                CredentialIssuerMetadataJsonParser.parseMetaData(json, SampleIssuer.Id)
            }
            val cause = assertIs<IllegalArgumentException>(exception.cause)
            assertEquals("Both JWT Proofs and Attestation Proofs must be supported", cause.message)
        }

        test("well-known/openid-credential-issuer_only_jwt_proof.json")
        test("well-known/openid-credential-issuer_only_attestation_proof.json")
    }
}
