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
import java.net.URL
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.time.Duration

class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val issuer: String,
    private val duration: Duration,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val headerCustomization: JWSHeader.Builder.(ClientAttestationIssuerRequest) -> Unit = {},
) {
    init {
        ClientAttestationPoPJWTSpec.requireIsAllowedAlgorithm(algorithm)
        require(duration.isPositive()) { "Duration must be positive" }
    }

    fun build(client: ClientAttestationIssuerRequest): ClientAttestationJWT {
        val header =
            JWSHeader.Builder(algorithm).apply {
                headerCustomization(client)
            }.build()

        val claims =
            JWTClaimsSet.Builder().apply {
                val now = clock.instant()
                val exp = now.plusSeconds(duration.inWholeSeconds)
                issuer(issuer)
                subject(client.id)
                claim("cnf", cnf(client.pubKey.toPublicJWK()))
                issueTime(Date.from(now))
                expirationTime(Date.from(exp))
            }.build()

        val jwt =
            SignedJWT(header, claims).apply {
                sign(signer)
            }

        return ClientAttestationJWT(jwt)
    }
}

object ClientAttestationJWTProcessorFactory {

    private class ClaimsSetVerifier private constructor(
        private val clock: Clock,
        exactMatchClaims: JWTClaimsSet,
    ) : DefaultJWTClaimsVerifier<SecurityContext>(exactMatchClaims, requiredClaims) {

        override fun currentTime(): Date = Date.from(clock.instant())

        companion object {

            private val requiredClaims = setOf("iss", "sub", "exp", "cnf")
            operator fun invoke(
                clock: Clock,
                request: ClientAttestationIssuerRequest,
                attestationIssuerId: ClientId,
            ): ClaimsSetVerifier {
                val exactMatchClaims = JWTClaimsSet.Builder()
                    .issuer(attestationIssuerId)
                    .subject(request.id)
                    .claim("cnf", cnf(request.pubKey.toPublicJWK()))
                    .build()
                return ClaimsSetVerifier(clock, exactMatchClaims)
            }
        }
    }

    fun create(
        clock: Clock,
        client: ClientAttestationIssuerRequest,
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

internal fun JWTClaimsSet.cnfJwk(): JWK? {
    return getJSONObjectClaim("cnf")?.get("jwk")?.let {
        @Suppress("UNCHECKED_CAST")
        runCatching { JWK.parse(it as Map<String, *>) }.getOrNull()
    }
}

/**
 * Default implementation of [ClientAttestationPoPJWTBuilder]
 * Populates only the mandatory claims : `iss`, `exp`, `jit`, `aud` and the optional `iat`
 * In regard to JOSE header, only `alg` claim is being populated
 */
internal object DefaultClientAttestationPopJWTBuilder : ClientAttestationPoPJWTBuilder {

    override suspend fun buildClientAttestationPoPJWT(
        clock: Clock,
        client: Client.Attested,
        authServerId: URL,
    ): ClientAttestationPoPJWT {
        val header = client.popJwtHeader()
        val claimSet = client.popJwtClaimSet(authServerId, clock.instant())
        val jwt = SignedJWT(header, claimSet).apply { sign(client.popJwtSpec.jwsSigner) }
        return ClientAttestationPoPJWT(jwt)
    }

    private fun Client.Attested.popJwtHeader(): JWSHeader =
        JWSHeader.Builder(popJwtSpec.signingAlgorithm).apply {
            popJwtSpec.typ?.let { type(JOSEObjectType(it)) }
        }.build()

    private fun Client.Attested.popJwtClaimSet(authServerId: URL, now: Instant): JWTClaimsSet {
        fun randomJwtId() = JWTID().value
        return JWTClaimsSet.Builder().apply {
            val exp = now.plusSeconds(popJwtSpec.duration.inWholeSeconds)
            issuer(id)
            jwtID(randomJwtId())
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
            audience(authServerId.toString())
        }.build()
    }
}
