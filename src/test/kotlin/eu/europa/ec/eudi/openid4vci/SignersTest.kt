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
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Serializable
data class JwtPayload(
    val iss: String,
    val sub: String,
    val aud: String,
    val jti: String,
)

class SignersTest {
    @Test
    fun `sign jwt and verify signature`() = runTest {
        val ecKey = CryptoGenerator.randomECSigningKey(Curve.P_256)

        val jwtBindingKey: JwtBindingKey = JwtBindingKey.Jwk(
            ecKey.toPublicJWK(),
        )

        val jwtSigner = DefaultSingleJwtSigner.popSigner<JwtPayload> (
            Signer.fromNimbusEcKey(
                ecKey,
                jwtBindingKey,
                secureRandom = null,
                provider = null,
            ),
        )

        val signResult = jwtSigner.sign(
            JwtPayload(
                iss = "https://eudiw.dev",
                sub = "subject",
                aud = "audience",
                jti = "unique-id",
            ),
        )

        val signedJWT = SignedJWT.parse(signResult.getOrThrow())

        assertEquals(JWSObject.State.SIGNED, signedJWT.state)
        assertTrue(signedJWT.verify(ECDSAVerifier(ecKey.toPublicJWK())))
    }
}
