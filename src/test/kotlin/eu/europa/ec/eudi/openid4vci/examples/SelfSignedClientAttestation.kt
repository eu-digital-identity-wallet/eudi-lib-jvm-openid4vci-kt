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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.requireIsNotMAC
import java.time.Clock
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

internal fun selfSignedClient(
    clock: Clock = Clock.systemDefaultZone(),
    privateKey: ECKey,
    clientId: String,
    duration: Duration = 10.minutes,
    headerCustomization: JWSHeader.Builder.() -> Unit = {},
): Client.Attested {
    require(privateKey.curve == Curve.P_256)
    val algorithm = JWSAlgorithm.ES256
    val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
    val clientAttestationJWT = run {
        val claims = ClientAttestationClaims(
            issuer = clientId,
            clientId = clientId,
            privateKey.toPublicJWK(),
        )
        val builder = ClientAttestationJwtBuilder(clock, duration, algorithm, signer, claims, headerCustomization)
        builder.build()
    }
    val popJwtSpec = ClientAttestationPoPJWTSpec(
        JWSAlgorithm.ES256,
        duration,
        null,
        signer,
    )
    return Client.Attested(clientAttestationJWT, popJwtSpec)
}

internal data class ClientAttestationClaims(
    val issuer: String,
    val clientId: ClientId,
    val pubKey: JWK,
) {

    init {
        require(clientId.isNotBlank() && clientId.isNotEmpty()) { "clientId cannot be blank" }
        require(!pubKey.isPrivate) { "InstanceKey should be public" }
    }
}

private class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val duration: Duration,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val claims: ClientAttestationClaims,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        require(duration.isPositive()) { "Duration must be positive" }
        requireIsNotMAC(algorithm)
    }

    fun build(): ClientAttestationJWT {
        val header = jwsHeader()
        val jwtClaimSet = claimSetForm(claims)
        val jwt =
            SignedJWT(header, jwtClaimSet).apply {
                sign(signer)
            }

        return ClientAttestationJWT(jwt)
    }

    private fun jwsHeader(): JWSHeader =
        JWSHeader.Builder(algorithm).apply {
            headerCustomization
        }.build()

    private fun claimSetForm(claims: ClientAttestationClaims): JWTClaimsSet =
        JWTClaimsSet.Builder().apply {
            val now = clock.instant()
            val exp = now.plusSeconds(duration.inWholeSeconds)
            issuer(claims.issuer)
            subject(claims.clientId)
            claim("cnf", cnf(claims.pubKey.toPublicJWK()))
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
        }.build()

    companion object {
        fun ecKey256(
            clock: Clock,
            duration: Duration,
            claims: ClientAttestationClaims,
            headerCustomization: JWSHeader.Builder.() -> Unit = {},
            privateKey: ECKey,
        ): ClientAttestationJwtBuilder {
            require(privateKey.curve == Curve.P_256)
            val algorithm = JWSAlgorithm.ES256
            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
            return ClientAttestationJwtBuilder(clock, duration, algorithm, signer, claims, headerCustomization)
        }
    }
}

internal fun cnf(jwk: JWK): Map<String, Any> =
    mapOf("jwk" to jwk.toJSONObject())
