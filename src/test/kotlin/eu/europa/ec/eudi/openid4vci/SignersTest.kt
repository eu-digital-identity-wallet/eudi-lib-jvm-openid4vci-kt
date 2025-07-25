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

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.keyAttestationJwt
import eu.europa.ec.eudi.openid4vci.internal.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Nested
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SignersTest {

    @Nested
    inner class JwtSigners {

        @Test
        fun `sign single jwt proof`() = runTest {
            val ecKey = CryptoGenerator.randomECSigningKey(Curve.P_256)

            val signer = Signer.fromNimbusEcKey(
                ecKey,
                JwtBindingKey.Jwk(ecKey.toPublicJWK()),
                secureRandom = null,
                provider = null,
            )

            val jwtSigner = JwtSigner<JwtProofClaims, JwtBindingKey>(
                algorithm = Curve.P_256.toJavaSigningAlg().toJoseAlg(),
                signOperation = signer.authenticate(),
            )

            val signResult = jwtSigner.sign(
                JwtProofClaims(
                    issuer = "https://eudiw.dev",
                    audience = "audience",
                    issuedAt = Instant.now(),
                    nonce = null,
                ),
            )

            val signedJwt = SignedJWT.parse(signResult)

            assertEquals(JWSObject.State.SIGNED, signedJwt.state)
        }

        @Test
        fun `sign batch jwt proofs and verify`() = runTest {
            val ecKeys = List(5) { CryptoGenerator.randomECSigningKey(Curve.P_256) }

            val batchSigner = BatchSigner.fromNimbusEcKeys(
                ecKeyPairs = ecKeys.associateWith { JwtBindingKey.Jwk(it.toPublicJWK()) },
                secureRandom = null,
                provider = null,
            )

            val batchJwtSigner = JwtBatchSigner<JwtProofClaims, JwtBindingKey>(
                algorithm = Curve.P_256.toJavaSigningAlg().toJoseAlg(),
                batchSignOperation = batchSigner.authenticate(),
            )

            val signResult = batchJwtSigner.sign(
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

    @Nested
    inner class JwtProofSigners {
        @Test
        fun `sign EC key attestation jwt proof`() = runTest {
            val ecKey = CryptoGenerator.randomECSigningKey(Curve.P_256)

            val signer = Signer.fromNimbusEcKey(
                ecKey,
                keyAttestationJwt(
                    attestedKeys = listOf(ecKey.toPublicJWK()),
                ),
                secureRandom = null,
                provider = null,
            )

            val keyAttestationJwtProofSigner = KeyAttestationJwtProofSigner(
                algorithm = Curve.P_256.toJavaSigningAlg().toJoseAlg(),
                signOperation = signer.authenticate(),
                keyIndex = 0,
            )

            val claims = JwtProofClaims(
                issuer = "https://eudiw.dev",
                audience = "audience",
                issuedAt = Instant.now(),
                nonce = "nonce",
            )
            val jwt = keyAttestationJwtProofSigner.sign(claims)
            val signedJwt = SignedJWT.parse(jwt)
            assertEquals(JWSObject.State.SIGNED, signedJwt.state)
            assertTrue(signedJwt.header.getCustomParam("key_attestation") is String)
        }
    }
}
