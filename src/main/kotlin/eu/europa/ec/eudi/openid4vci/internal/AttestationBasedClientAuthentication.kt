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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.*
import java.time.Clock
import java.util.*
import kotlin.time.Duration

internal class SelfAttestedIssuer(
    private val clock: Clock,
    private val attestationDuration: Duration,
    private val typ: JOSEObjectType = JOSEObjectType.JWT,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) : ClientAttestationIssuer {

    override suspend fun issue(client: Client.Attested): ClientAttestationJWT {
        val signer = DefaultJWSSignerFactory().createJWSSigner(client.instanceKey, client.popSigningAlgorithm)
        val builder = ClientAttestationJwtBuilder(
            clock = clock,
            issuer = client.id,
            duration = attestationDuration,
            algorithm = client.popSigningAlgorithm,
            signer = signer,
            typ = typ,
            headerCustomization = headerCustomization,
        )
        return builder.build(client)
    }
}

internal class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val issuer: String,
    private val duration: Duration,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val typ: JOSEObjectType = JOSEObjectType.JWT,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        require(
            algorithm in ECDSAVerifier.SUPPORTED_ALGORITHMS ||
                algorithm in RSASSAVerifier.SUPPORTED_ALGORITHMS,
        )
        require(duration.isPositive()) { "Duration must be positive" }
    }

    fun build(client: Client.Attested): ClientAttestationJWT {
        require(client.id.isNotBlank()) { "Wallet id cannot be blank" }

        val header = with(JWSHeader.Builder(algorithm)) {
            type(typ)
            headerCustomization()
            build()
        }
        val now = clock.instant()
        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject(client.id)
            .claim("cnf", cnf(client.instanceKey.toPublicJWK()))
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(duration.inWholeSeconds)))
            .build()
        val jwt = SignedJWT(header, claims).apply { sign(signer) }
        return ClientAttestationJWT(jwt)
    }
}

object ClientAttestationJWTProcessorFactory {

    private class ClaimsSetVerifier private constructor(
        private val clock: Clock,
        exactMatchClaims: JWTClaimsSet,
    ) : DefaultJWTClaimsVerifier<SecurityContext>(exactMatchClaims, requiredClaims) {

        override fun currentTime(): Date {
            return Date.from(clock.instant())
        }

        companion object {

            private val requiredClaims = setOf("iss", "sub", "exp", "cnf")
            operator fun invoke(
                clock: Clock,
                request: Client.Attested,
                attestationIssuerId: ClientId,
            ): ClaimsSetVerifier {
                val exactMatchClaims = JWTClaimsSet.Builder()
                    .issuer(attestationIssuerId)
                    .subject(request.id)
                    .claim("cnf", cnf(request.instanceKey.toPublicJWK()))
                    .build()
                return ClaimsSetVerifier(clock, exactMatchClaims)
            }
        }
    }

    fun create(
        clock: Clock,
        client: Client.Attested,
        attestationIssuerId: ClientId,
        jwsTypeJWSVerifier: JOSEObjectTypeVerifier<SecurityContext> = DefaultJOSEObjectTypeVerifier.JWT,
        attestationIssuerKeySelector: JWSKeySelector<SecurityContext>,
    ): JWTProcessor<SecurityContext> = DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = jwsTypeJWSVerifier
        jwsKeySelector = attestationIssuerKeySelector
        jwtClaimsSetVerifier = ClaimsSetVerifier(clock, client, attestationIssuerId)
    }
}

private fun cnf(jwk: JWK): Map<String, Any> =
    mapOf("jwk" to jwk.toJSONObject())

class DefaultClientAttestationPopBuilder(
    private val clock: Clock,
    private val duration: Duration,

) : ClientAttestationPoPBuilder {

    init {
        require(duration.isPositive())
    }

    override suspend fun issue(client: Client.Attested, authServerId: String): ClientAttestationPoP {
        val header = JWSHeader.Builder(client.popSigningAlgorithm).build()

        val now = clock.instant()
        val exp = now.plusSeconds(duration.inWholeSeconds)
        val claimSet = JWTClaimsSet.Builder().apply {
            issuer(client.id)
            jwtID(JWTID().value)
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
            audience(authServerId)
        }.build()
        val signer = DefaultJWSSignerFactory().createJWSSigner(client.instanceKey, client.popSigningAlgorithm)
        val jwt = SignedJWT(header, claimSet).apply { sign(signer) }
        return ClientAttestationPoP(jwt)
    }
}
