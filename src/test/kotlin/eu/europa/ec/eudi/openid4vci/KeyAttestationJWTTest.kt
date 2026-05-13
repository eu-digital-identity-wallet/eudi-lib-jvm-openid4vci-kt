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
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.randomECSigningKey
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.MissingFieldException
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.net.URL
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.collections.map
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

@OptIn(ExperimentalSerializationApi::class)
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
    fun `KeyAttestationJWT must have all required claim`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .build()
            .apply {
                sign(signer)
            }
        val exception = assertThrows<IllegalArgumentException> { KeyAttestationJWT(jwt) }
        assertEquals("Invalid Claims Set.", exception.message)
        val cause = assertIs<MissingFieldException>(exception.cause)

        val requiredFields = listOf(
            RFC7519.ISSUED_AT,
            RFC7519.EXPIRATION_TIME,
            OpenId4VCISpec.ATTESTED_KEYS,
            OpenId4VCISpec.KEY_STORAGE,
            OpenId4VCISpec.USER_AUTHENTICATION,
            OpenId4VCISpec.CERTIFICATION,
            TS3.KEY_STORAGE_STATUS,
        )
        assertEquals(requiredFields.size, cause.missingFields.size)
        assertTrue(cause.missingFields.containsAll(requiredFields))
    }

    @Test
    fun `KeyAttestationJWT must contain at least 1 attested keys claim`() {
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
            .build()
            .apply {
                sign(signer)
            }

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
    fun `KeyAttestationJWT must contain iso_18045_high in key_storage claim`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .iat(Instant.now())
            .exp(Instant.now() + Duration.ofDays(1L))
            .attestedKeys(listOf(ECKeyGenerator(Curve.P_256).generate().toPublicJWK()))
            .keyStorage(listOf(AttackPotentialResistance.Iso18045Moderate))
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
        assertEquals("keyStorage must contain [iso_18045_high]", cause.message)
    }

    @Test
    fun `KeyAttestationJWT must contain iso_18045_high in user_authentication claim`() {
        val jwt = KeyAttestationJWTBuilder(JWSAlgorithm.ES256)
            .typ(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            .iat(Instant.now())
            .exp(Instant.now() + Duration.ofDays(1L))
            .attestedKeys(listOf(ECKeyGenerator(Curve.P_256).generate().toPublicJWK()))
            .keyStorage(listOf(AttackPotentialResistance.Iso18045High))
            .userAuthentication(listOf(AttackPotentialResistance.Iso18045Moderate))
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
        assertEquals("userAuthentication must contain [iso_18045_high]", cause.message)
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
            .build()
            .apply {
                sign(signer)
            }

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

        assertEquals(expectedClaimsSet, keyAttestationJwt.claimsSet)
    }

    @Test
    fun `KeyAttestationJWT must be signed with an allowed algorithm`() {
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
                .build()
                .apply {
                    sign(signer)
                }
            return KeyAttestationJWT(jwt)
        }

        // ES256, ES384, ES512 is allowed -- ES256K is deprecated
        create(JWSAlgorithm.ES256, ECDSASigner(ECKeyGenerator(Curve.P_256).generate()))
        create(JWSAlgorithm.ES384, ECDSASigner(ECKeyGenerator(Curve.P_384).generate()))
        create(JWSAlgorithm.ES512, ECDSASigner(ECKeyGenerator(Curve.P_521).generate()))

        // RS256, RS384, RS512, PS256, PS384, PS512 is not allowed
        val rsaSigner = RSASSASigner(RSAKeyGenerator(2048).generate())
        listOf(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512, JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512)
            .forEach {
                val exception = assertThrows<IllegalArgumentException> { create(it, rsaSigner) }
                assertEquals("Signature algorithm must be one of [ES256, ES384, ES512]", exception.message)
            }

        // HS256, HS384, HS512 is not allowed
        val macSigner = MACSigner(Random.nextBytes(512))
        listOf(JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512)
            .forEach {
                val exception = assertThrows<IllegalArgumentException> { create(it, macSigner) }
                assertEquals("Signature algorithm must be one of [ES256, ES384, ES512]", exception.message)
            }

        // EdDSA, Ed25519 is not allowed -- Nimbus does not provide a JWSSigner for Ed448
        val ed25519Signer = Ed25519Signer(OctetKeyPairGenerator(Curve.Ed25519).generate())
        listOf(JWSAlgorithm.EdDSA, JWSAlgorithm.Ed25519)
            .forEach {
                val exception = assertThrows<IllegalArgumentException> { create(it, ed25519Signer) }
                assertEquals("Signature algorithm must be one of [ES256, ES384, ES512]", exception.message)
            }
    }
}

private class KeyAttestationJWTBuilder(signatureAlgorithm: JWSAlgorithm) {
    private val header = JWSHeader.Builder(signatureAlgorithm)
    private val claimsSet = JWTClaimsSet.Builder()

    fun typ(typ: JOSEObjectType): KeyAttestationJWTBuilder = apply {
        header.type(typ)
    }

    fun iat(iat: Instant): KeyAttestationJWTBuilder = apply {
        claimsSet.issueTime(Date.from(iat))
    }

    fun exp(exp: Instant): KeyAttestationJWTBuilder = apply {
        claimsSet.expirationTime(Date.from(exp))
    }

    fun attestedKeys(attestedKeys: List<JWK>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.ATTESTED_KEYS, attestedKeys.map { it.toJSONObject() })
    }

    fun keyStorage(keyStorage: List<AttackPotentialResistance>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.KEY_STORAGE, keyStorage.map { it.value })
    }

    fun userAuthentication(userAuthentication: List<AttackPotentialResistance>): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.USER_AUTHENTICATION, userAuthentication.map { it.value })
    }

    fun certification(certification: URL): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.CERTIFICATION, certification.toExternalForm())
    }

    fun nonce(nonce: Nonce): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(OpenId4VCISpec.NONCE, nonce.value)
    }

    fun status(status: StatusClaim): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(TokenStatusListSpec.STATUS, JSONObjectUtils.parse(JsonSupport.encodeToString(status)))
    }

    fun keyStorageStatus(keyStorageStatus: KeyStorageStatus): KeyAttestationJWTBuilder = apply {
        claimsSet.claim(TS3.KEY_STORAGE_STATUS, JSONObjectUtils.parse(JsonSupport.encodeToString(keyStorageStatus)))
    }

    fun build(): SignedJWT = SignedJWT(header.build(), claimsSet.build())
}
