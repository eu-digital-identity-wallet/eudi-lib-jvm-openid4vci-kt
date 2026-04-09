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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.randomECSigningKey
import org.junit.jupiter.api.assertThrows
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals

private class KeyAttestationJWTTest {

    val ecKeyJwk = randomECSigningKey(Curve.P_256)
    val signer: JWSSigner = ECDSASigner(
        ecKeyJwk.toECKey(),
    )

    @Test
    fun `KeyAttestationJWT should be signed`() {
        val signedJwt = SignedJWT(
            JWSHeader(JWSAlgorithm.ES256),
            JWTClaimsSet.Builder()
                .build(),
        )
        assertThrows<IllegalStateException> { KeyAttestationJWT(signedJwt.serialize()) }
    }

    @Test
    fun `KeyAttestationJWT should have correct type`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .build(),
            JWTClaimsSet.Builder()
                .build(),
        ).apply { sign(signer) }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(signedJwt.serialize()) }
        assertEquals("Invalid Key Attestation JWT. Type must be set to `$OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE`", exception.message)
    }

    @Test
    fun `KeyAttestationJWT should have iat claim`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .build(),
        ).apply { sign(signer) }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(signedJwt.serialize()) }
        assertEquals("Invalid Key Attestation JWT. Misses `iat` claim", exception.message)
    }

    @Test
    fun `KeyAttestationJWT should have attested keys claim`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .build(),
        ).apply { sign(signer) }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(signedJwt.serialize()) }
        assertEquals("Invalid Key Attestation JWT. Misses `attested_keys` claim", exception.message)
    }

    @Test
    fun `KeyAttestationJWT should have valid attested keys claim`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .claim("attested_keys", listOf("jwk1", "jwk2"))
                .build(),
        ).apply { sign(signer) }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(signedJwt.serialize()) }
        assertEquals("Invalid Key Attestation JWT. Item at index 0 in `attested_keys` is not a JSON object.", exception.message)
    }

    @Test
    fun `KeyAttestationJWT should not have private keys in the attested keys claim`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .claim("attested_keys", listOf(ecKeyJwk.toJSONObject()))
                .build(),
        ).apply { sign(signer) }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(signedJwt.serialize()) }
        assertEquals("Invalid Key Attestation JWT. Item at index 0 in `attested_keys` must be a public key.", exception.message)
    }

    @Test
    fun `KeyAttestationJWT should be created when valid`() {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .claim("attested_keys", listOf(ecKeyJwk.toPublicJWK().toJSONObject()))
                .build(),
        ).apply { sign(signer) }
        KeyAttestationJWT(signedJwt.serialize())
    }
}
