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
import eu.europa.ec.eudi.openid4vci.internal.JwtProofSigner
import eu.europa.ec.eudi.openid4vci.internal.JwtProofsSigner
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKey
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKeys
import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class SignersTest {

    @Test
    fun `sign single jwt proof`() = runTest {
        val ecKey = CryptoGenerator.randomECSigningKey(Curve.P_256)

        val jwtProofSigner = JwtProofSigner(
            Signer.fromNimbusEcKey(
                ecKey,
                JwtBindingKey.Jwk(ecKey.toPublicJWK()),
                secureRandom = null,
                provider = null,
            ),
        )

        val signResult = jwtProofSigner.sign(
            JwtProofClaims(
                issuer = "https://eudiw.dev",
                audience = "audience",
                issuedAt = Instant.now(),
                nonce = null,
            ),
        )

        val signedJwt = SignedJWT.parse(signResult)

        assertEquals(
            ecKey.toPublicJWK().toJSONString(),
            signedJwt.header.jwk.toJSONString(),
        )
    }

    @Test
    fun `sign batch jwt proofs and verify`() = runTest {
        val ecKeys = List(5) { CryptoGenerator.randomECSigningKey(Curve.P_256) }

        val jwtProofSigner = JwtProofsSigner(
            BatchSigner.fromNimbusEcKeys(
                ecKeyPairs = ecKeys.associateWith { JwtBindingKey.Jwk(it.toPublicJWK()) },
                secureRandom = null,
                provider = null,
            ),
        )

        val signResult = jwtProofSigner.sign(
            JwtProofClaims(
                issuer = "https://eudiw.dev",
                audience = "audience",
                issuedAt = Instant.now(),
                nonce = null,
            ),
        )

        assertEquals(5, signResult.size)
    }
}
