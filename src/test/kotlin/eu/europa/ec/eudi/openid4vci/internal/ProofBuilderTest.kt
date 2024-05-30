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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.universityDegreeJwt
import kotlinx.coroutines.test.runTest
import java.time.Clock
import kotlin.test.*

/**
 * Test cases for [ProofBuilder].
 */
internal class ProofBuilderTest {

    @Test
    fun `proof is successfully generated when signing algorithm is supported by the issuer`() = runTest {
        val signingAlgorithm = JWSAlgorithm.RS256
        val credentialConfiguration = universityDegreeJwt()
        val proofTypeMeta = credentialConfiguration.proofTypesSupported
            .values.filterIsInstance<ProofTypeMeta.Jwt>()
            .firstOrNull()
        assertNotNull(proofTypeMeta)

        assertTrue { signingAlgorithm in proofTypeMeta.algorithms }

        val signer = CryptoGenerator.rsaProofSigner(signingAlgorithm)

        JwtProofBuilder(
            Clock.systemDefaultZone(),
            iss = "https://wallet",
            aud = CredentialIssuerId("https://issuer").getOrThrow(),
            nonce = CNonce("nonce"),
            signer,
        ).build()
    }

    @Test
    fun `proof is not generated when signing algorithm is not supported by the issuer`() = runTest {
        val signingAlgorithm = JWSAlgorithm.RS512
        val credentialConfiguration = universityDegreeJwt()
        val proofTypeMeta = credentialConfiguration.proofTypesSupported
            .values.filterIsInstance<ProofTypeMeta.Jwt>()
            .firstOrNull()
        assertNotNull(proofTypeMeta)
        assertFalse { signingAlgorithm in proofTypeMeta.algorithms }

        val signer = CryptoGenerator.rsaProofSigner(signingAlgorithm)
        assertFailsWith(CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported::class) {
            JwtProofBuilder.check(signer, credentialConfiguration.proofTypesSupported)
        }
    }
}
