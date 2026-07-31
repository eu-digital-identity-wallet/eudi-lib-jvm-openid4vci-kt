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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.KeyAttestationRequirement
import eu.europa.ec.eudi.openid4vci.ProofTypeMeta
import eu.europa.ec.eudi.openid4vci.ProofTypesSupported
import eu.europa.ec.eudi.openid4vci.ProofsConfig
import kotlin.test.Test
import kotlin.test.assertFailsWith

/**
 * Test cases for [ProofsConfig.ensureCompatibleWith].
 *
 * Issuers may advertise only one of the two proof types (JWT or Attestation). The compatibility
 * check must treat a proof type that the issuer does not advertise as unsupported, rather than
 * failing with a [ClassCastException] (or, worse, accepting it).
 */
class ProofsConfigCompatibilityTest {

    @Test
    fun `passes when issuer requires no proofs and wallet supports no-proof issuance`() {
        walletSupporting(noProof = true).ensureCompatibleWith(ProofTypesSupported.Empty)
    }

    @Test
    fun `fails when issuer requires no proofs but wallet does not support no-proof issuance`() {
        assertFailsWith<IllegalArgumentException> {
            walletSupporting(noProof = false, jwt = setOf(JWSAlgorithm.ES256))
                .ensureCompatibleWith(ProofTypesSupported.Empty)
        }
    }

    @Test
    fun `passes when issuer supports only JWT proofs and wallet supports both proof types`() {
        walletSupporting(jwt = setOf(JWSAlgorithm.ES256), attestation = setOf(JWSAlgorithm.ES256))
            .ensureCompatibleWith(issuerSupporting(jwt = listOf(JWSAlgorithm.ES256)))
    }

    @Test
    fun `passes when issuer supports only Attestation proofs and wallet supports both proof types`() {
        walletSupporting(jwt = setOf(JWSAlgorithm.ES256), attestation = setOf(JWSAlgorithm.ES256))
            .ensureCompatibleWith(issuerSupporting(attestation = listOf(JWSAlgorithm.ES256)))
    }

    @Test
    fun `fails when issuer supports only JWT proofs but wallet supports only Attestation proofs`() {
        assertFailsWith<IllegalArgumentException> {
            walletSupporting(attestation = setOf(JWSAlgorithm.ES256))
                .ensureCompatibleWith(issuerSupporting(jwt = listOf(JWSAlgorithm.ES256)))
        }
    }

    @Test
    fun `fails when issuer supports only Attestation proofs but wallet supports only JWT proofs`() {
        assertFailsWith<IllegalArgumentException> {
            walletSupporting(jwt = setOf(JWSAlgorithm.ES256))
                .ensureCompatibleWith(issuerSupporting(attestation = listOf(JWSAlgorithm.ES256)))
        }
    }

    @Test
    fun `fails when the only shared proof type has no common algorithm`() {
        assertFailsWith<IllegalArgumentException> {
            walletSupporting(jwt = setOf(JWSAlgorithm.ES384))
                .ensureCompatibleWith(issuerSupporting(jwt = listOf(JWSAlgorithm.ES256)))
        }
    }

    @Test
    fun `passes when one of two advertised proof types matches the wallet`() {
        walletSupporting(jwt = setOf(JWSAlgorithm.ES256))
            .ensureCompatibleWith(
                issuerSupporting(
                    jwt = listOf(JWSAlgorithm.ES256),
                    attestation = listOf(JWSAlgorithm.ES512),
                ),
            )
    }

    private fun walletSupporting(
        noProof: Boolean = false,
        jwt: Set<JWSAlgorithm>? = null,
        attestation: Set<JWSAlgorithm>? = null,
    ): ProofsConfig =
        ProofsConfig(
            isNoProofSupported = noProof,
            jwtProof = jwt?.let { ProofsConfig.SupportedJwtProof(it) },
            attestationProof = attestation?.let { ProofsConfig.SupportedAttestationProof(it) },
        )

    private fun issuerSupporting(
        jwt: List<JWSAlgorithm>? = null,
        attestation: List<JWSAlgorithm>? = null,
    ): ProofTypesSupported =
        ProofTypesSupported(
            setOfNotNull(
                jwt?.let { ProofTypeMeta.Jwt(it, noKeyAttestationConstraints) },
                attestation?.let { ProofTypeMeta.Attestation(it, noKeyAttestationConstraints) },
            ),
        )

    private val noKeyAttestationConstraints = KeyAttestationRequirement(null, null, null)
}
