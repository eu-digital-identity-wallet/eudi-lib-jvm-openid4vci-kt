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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKey
import io.ktor.client.request.*
import kotlinx.serialization.json.JsonPrimitive
import java.security.Key
import java.time.Clock
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

internal val ECKey.jwsAlgorithm: JWSAlgorithm
    get() = when (curve) {
        Curve.P_256 -> JWSAlgorithm.ES256
        Curve.P_384 -> JWSAlgorithm.ES384
        Curve.P_521 -> JWSAlgorithm.ES512
        else -> error("Unsupported curve ${curve.name}")
    }

@Suppress("UNUSED")
internal fun selfSignedClient(
    clock: Clock = Clock.systemDefaultZone(),
    walletInstanceKey: ECKey,
    clientId: String,
    duration: Duration = 10.minutes,
    headerCustomization: JWSHeader.Builder.() -> Unit = {},
): ClientAuthentication.AttestationBased {
    val algorithm = walletInstanceKey.jwsAlgorithm
    val signer = DefaultJWSSignerFactory().createJWSSigner(walletInstanceKey, algorithm)
    val clientAttestationJWT = run {
        val now = clock.instant()
        val exp = now + duration.toJavaDuration()
        val claims = ClientAttestationJWTClaims(
            issuer = NonBlankString(clientId),
            subject = NonBlankString(clientId),
            expirationTime = exp,
            confirmation = Confirmation(jwk = walletInstanceKey.toPublicJWK()),
            issuedAt = now,
            notBefore = now,
            eudiWalletInfo = EudiWalletInfo(
                generalInfo = GeneralInfo(
                    walletProviderName = NonBlankString("ARF"),
                    walletSolutionId = NonBlankString("EUDIW"),
                    walletSolutionVersion = NonBlankString("0.0.1"),
                    walletSolutionCertificationInformation = WalletSolutionCertificationInformation(
                        JsonPrimitive("https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework"),
                    ),
                ),
            ),
        )
        val builder = ClientAttestationJwtBuilder(algorithm, signer, claims, headerCustomization)
        builder.build()
    }
    val popJwtSpec = ClientAttestationPoPJWTSpec(Signer.fromNimbusEcKey(walletInstanceKey, walletInstanceKey.toPublicJWK(), null, null))
    return ClientAuthentication.AttestationBased(clientAttestationJWT, popJwtSpec)
}

private class ClientAttestationJwtBuilder(
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val claims: ClientAttestationJWTClaims,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        requireIsNotMAC(algorithm)
    }

    fun build(): ClientAttestationJWT {
        val header = jwsHeader()
        val jwtClaimSet = claimsSetFrom(claims)
        val jwt =
            SignedJWT(header, jwtClaimSet).apply {
                sign(signer)
            }

        return ClientAttestationJWT(jwt)
    }

    private fun jwsHeader(): JWSHeader =
        JWSHeader.Builder(algorithm).apply {
            headerCustomization()
            type(JOSEObjectType(AttestationBasedClientAuthenticationSpec.ATTESTATION_JWT_TYPE))
        }.build()

    private fun claimsSetFrom(claims: ClientAttestationJWTClaims): JWTClaimsSet = JWTClaimsSet.parse(JsonSupport.encodeToString(claims))

    companion object {
        fun ecKey256(
            claims: ClientAttestationJWTClaims,
            headerCustomization: JWSHeader.Builder.() -> Unit = {},
            privateKey: ECKey,
        ): ClientAttestationJwtBuilder {
            require(privateKey.curve == Curve.P_256)
            val algorithm = JWSAlgorithm.ES256
            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
            return ClientAttestationJwtBuilder(algorithm, signer, claims, headerCustomization)
        }
    }
}

internal val JWK.publicKey: Key
    get() = when (this) {
        is ECKey -> toECPublicKey()
        is RSAKey -> toRSAPublicKey()
        else -> error("Unsupported JWK type")
    }

internal fun HttpRequestData.verifySelfSignedClientAttestation(walletInstanceKey: ECKey, challenge: Nonce?) {
    val clientAttestation = run {
        val jwt = SignedJWT.parse(assertNotNull(headers[AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_HEADER]))
            .apply {
                assertTrue(verify(ECDSAVerifier(walletInstanceKey)))
            }
        ClientAttestationJWT(jwt)
    }

    val clientAttestationPOP = run {
        val jwt = SignedJWT.parse(assertNotNull(headers[AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_POP_HEADER]))
            .apply {
                assertTrue(verify(ECDSAVerifier(walletInstanceKey)))
                assertTrue(verify(DefaultJWSVerifierFactory().createJWSVerifier(header, clientAttestation.publicKey.publicKey)))
            }
        ClientAttestationPoPJWT(jwt)
    }
    assertEquals(clientAttestation.clientId, clientAttestationPOP.clientId)
    if (null != challenge) {
        assertEquals(
            challenge.value,
            clientAttestationPOP.jwt.jwtClaimsSet.getStringClaim(AttestationBasedClientAuthenticationSpec.CHALLENGE_CLAIM),
        )
    } else {
        assertNull(clientAttestationPOP.jwt.jwtClaimsSet.getStringClaim(AttestationBasedClientAuthenticationSpec.CHALLENGE_CLAIM))
    }
}
