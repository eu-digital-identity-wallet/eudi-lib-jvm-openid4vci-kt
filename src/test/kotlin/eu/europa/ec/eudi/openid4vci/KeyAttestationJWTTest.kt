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
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.randomECSigningKey
import eu.europa.ec.eudi.openid4vci.internal.decodeAs
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class KeyAttestationJWTTest {

    val signingKey = randomECSigningKey(Curve.P_256)
    val signer: JWSSigner = ECDSASigner(signingKey.toECKey())

    @Test
    fun `KeyAttestationJWT must have correct type`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType.JOSE)
            .build()
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals(
            "Expected SignedJWT `typ` to be '${OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE}', but found '${JOSEObjectType.JOSE.type}' instead",
            exception.message,
        )
    }

    @Test
    fun `KeyAttestationJWT must be signed`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .build()
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals("Provided JWT is not signed", exception.message)
    }

    @Test
    fun `KeyAttestationJWT must have attested keys`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .build(signer)

        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals("Invalid Claims Set.", exception.message)

        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("Missing attested_keys claim", cause.message)
    }

    @Test
    fun `KeyAttestationJWT must contain at least 1 attested key`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .iat(Instant.now())
            .exp(Instant.now() + Duration.ofDays(1L))
            .attestedKeys(emptyList())
            .keyStorage(emptyList())
            .userAuthentication(emptyList())
            .certification(URI.create("https://example.org/certification/wscd/GlobalPlatform/").toURL())
            .keyStorageStatus(
                KeyStorageStatus(
                    StatusClaim(
                        StatusListTokenClaim(
                            7u,
                            URI.create("https://revocation_url/wua-type-statuslists/3"),
                        ),
                    ),
                    Instant.now() + Duration.ofDays(90L),
                ),
            )
            .build(signer)

        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals("Invalid Claims Set.", exception.message)

        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("attestedKeys must not be empty", cause.message)
    }

    @Test
    fun `KeyAttestationJWT must not have private keys in the attested keys claim`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .iat(Instant.now())
            .exp(Instant.now() + Duration.ofDays(1L))
            .attestedKeys(listOf(ECKeyGenerator(Curve.P_256).generate()))
            .keyStorage(emptyList())
            .userAuthentication(emptyList())
            .certification(URI.create("https://example.org/certification/wscd/GlobalPlatform/").toURL())
            .keyStorageStatus(
                KeyStorageStatus(
                    StatusClaim(
                        StatusListTokenClaim(
                            7u,
                            URI.create("https://revocation_url/wua-type-statuslists/3"),
                        ),
                    ),
                    Instant.now() + Duration.ofDays(90L),
                ),
            )
            .build()
            .apply {
                sign(signer)
            }

        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals("Invalid Claims Set.", exception.message)

        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("attestedKeys must all be public", cause.message)
    }

    @Test
    fun `KeyAttestationJWT must be created when valid`() {
        val now = Instant.ofEpochSecond(Instant.now().epochSecond) // drop fraction of seconds, they cannot be encoded in a JWT
        val iat = now
        val exp = now + Duration.ofDays(1L)
        val attestedKeys = listOf(ECKeyGenerator(Curve.P_256).generate().toPublicJWK())
        val keyStorage = listOf(AttackPotentialResistance.Iso18045High)
        val userAuthentication = listOf(AttackPotentialResistance.Iso18045High)
        val certification = URI.create("https://example.org/certification/wscd/GlobalPlatform/").toURL()
        val keyStorageStatus = KeyStorageStatus(
            StatusClaim(
                StatusListTokenClaim(
                    7u,
                    URI.create("https://revocation_url/wua-type-statuslists/3"),
                ),
            ),
            now + Duration.ofDays(90L),
        )
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .iat(iat)
            .exp(exp)
            .attestedKeys(attestedKeys)
            .keyStorage(keyStorage)
            .userAuthentication(userAuthentication)
            .certification(certification)
            .keyStorageStatus(keyStorageStatus)
            .build(signer)

        val keyAttestationJwt = KeyAttestationJWT(jwt)
        val expectedClaimsSet = KeyAttestationJWTClaims(
            issuedAt = iat,
            expiresAt = exp,
            AttestedKeys(attestedKeys),
            keyStorage = keyStorage,
            userAuthentication = userAuthentication,
            certification,
            null,
            null,
            keyStorageStatus,
        )

        assertEquals(expectedClaimsSet, keyAttestationJwt.claimsSet.decodeAs<KeyAttestationJWTClaims>().getOrThrow())
    }

    @Test
    fun `KeyAttestationJWT can be signed with any algorithm`() {
        fun create(algorithm: JWSAlgorithm, signer: JWSSigner): KeyAttestationJWT {
            val jwt = KeyAttestationJWTBuilder(algorithm)
                .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
                .iat(Instant.now())
                .exp(Instant.now() + Duration.ofDays(1L))
                .attestedKeys(listOf(ECKeyGenerator(Curve.P_256).generate().toPublicJWK()))
                .keyStorage(listOf(AttackPotentialResistance.Iso18045High))
                .userAuthentication(listOf(AttackPotentialResistance.Iso18045High))
                .certification(URI.create("https://example.org/certification/wscd/GlobalPlatform/").toURL())
                .keyStorageStatus(
                    KeyStorageStatus(
                        StatusClaim(
                            StatusListTokenClaim(
                                7u,
                                URI.create("https://revocation_url/wua-type-statuslists/3"),
                            ),
                        ),
                        Instant.now() + Duration.ofDays(90L),
                    ),
                )
                .build(signer)
            return KeyAttestationJWT(jwt)
        }

        // ES256, ES384, ES512 -- ES256K is deprecated
        create(JWSAlgorithm.ES256, ECDSASigner(ECKeyGenerator(Curve.P_256).generate()))
        create(JWSAlgorithm.ES384, ECDSASigner(ECKeyGenerator(Curve.P_384).generate()))
        create(JWSAlgorithm.ES512, ECDSASigner(ECKeyGenerator(Curve.P_521).generate()))

        // RS256, RS384, RS512, PS256, PS384, PS512
        val rsaSigner = RSASSASigner(RSAKeyGenerator(2048).generate())
        listOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512)
            .forEach {
                create(it, rsaSigner)
            }

        // HS256, HS384, HS512
        val macSigner = MACSigner(Random.nextBytes(512))
        listOf(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512)
            .forEach {
                create(it, macSigner)
            }

        // EdDSA, Ed25519 -- Nimbus does not provide a JWSSigner for Ed448
        val ed25519Signer = Ed25519Signer(OctetKeyPairGenerator(Curve.Ed25519).generate())
        listOf(JWSAlgorithm.EdDSA, JWSAlgorithm.Ed25519)
            .forEach {
                create(it, ed25519Signer)
            }
    }
}
