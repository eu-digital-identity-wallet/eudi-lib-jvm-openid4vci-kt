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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.produce.JWSSignerFactory
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
    supportedSigningAlgorithms: Set<JWSAlgorithm> = DefaultSupportedSigningAlgorithms,
    private val attestationDuration: Duration,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) : ClientAttestationIssuer {
    init {
        require(supportedSigningAlgorithms.isNotEmpty()) {
            "supportedSigningAlgorithms cannot be empty"
        }
        require(supportedSigningAlgorithms.all { it !in MACSigner.SUPPORTED_ALGORITHMS }) {
            "MAC algorithms are not allowed"
        }
        require(attestationDuration.isPositive()) {
            "Attestation duration must be positive"
        }
    }

    private val signerFactory = jwsSignerFactoryFor(supportedSigningAlgorithms)

    override suspend fun issue(clock: Clock, client: Client.Attested): ClientAttestationJWT {
        val (clientId, instanceKey, popSigningAlgorithm) = client
        val signer = signerFactory.createJWSSigner(instanceKey, popSigningAlgorithm)
        val builder = ClientAttestationJwtBuilder(
            clock = clock,
            issuer = clientId,
            duration = attestationDuration,
            algorithm = popSigningAlgorithm,
            signer = signer,
            headerCustomization = headerCustomization,
        )
        return builder.build(client)
    }

    companion object {
        val DefaultSupportedSigningAlgorithms =
            ECDSASigner.SUPPORTED_ALGORITHMS + RSASSASigner.SUPPORTED_ALGORITHMS + Ed25519Signer.SUPPORTED_ALGORITHMS
    }
}

internal class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val issuer: String,
    private val duration: Duration,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        require(algorithm !in MACSigner.SUPPORTED_ALGORITHMS)
        require(duration.isPositive()) { "Duration must be positive" }
    }

    fun build(client: Client.Attested): ClientAttestationJWT {
        require(client.id.isNotBlank()) { "Wallet id cannot be blank" }

        val header = JWSHeader.Builder(algorithm).apply {
            headerCustomization()
        }.build()

        val claims = JWTClaimsSet.Builder().apply {
            val now = clock.instant()
            val exp = now.plusSeconds(duration.inWholeSeconds)
            issuer(issuer)
            subject(client.id)
            claim("cnf", cnf(client.instanceKey.toPublicJWK()))
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
        }.build()

        val jwt = SignedJWT(header, claims).apply {
            sign(signer)
        }
        return ClientAttestationJWT(jwt)
    }
}

internal object ClientAttestationJWTProcessorFactory {

    private class ClaimsSetVerifier private constructor(
        private val clock: Clock,
        exactMatchClaims: JWTClaimsSet,
    ) : DefaultJWTClaimsVerifier<SecurityContext>(exactMatchClaims, requiredClaims) {

        override fun currentTime(): Date = Date.from(clock.instant())

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

/**
 * Default implementation of [ClientAttestationPoPJWTBuilder]
 * Populates only the mandatory claims : `iss`, `exp`, `jit`, `aud` and the optional `iat`
 * In regard to JOSE header, only `alg` claim is being populated
 */
internal object DefaultClientAttestationPopBuilder : ClientAttestationPoPJWTBuilder {

    override suspend fun build(
        clock: Clock,
        client: Client.Attested,
        authServerId: String,
        duration: Duration,
        jwtId: String?,
    ): ClientAttestationPoPJWT {
        require(duration.isPositive()) { "duration must be positive" }
        fun randomJwtId() = JWTID().value
        val (clientId, instanceKey, popSigningAlgorithm) = client
        val header = JWSHeader.Builder(popSigningAlgorithm).build()
        val claimSet = JWTClaimsSet.Builder().apply {
            val now = clock.instant()
            val exp = now.plusSeconds(duration.inWholeSeconds)
            issuer(clientId)
            jwtID(jwtId ?: randomJwtId())
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
            audience(authServerId)
        }.build()
        val jwt = SignedJWT(header, claimSet).apply {
            val signerFactory = jwsSignerFactoryFor(setOf(popSigningAlgorithm))
            val signer = signerFactory.createJWSSigner(instanceKey, popSigningAlgorithm)
            sign(signer)
        }
        return ClientAttestationPoPJWT(jwt)
    }
}

private fun jwsSignerFactoryFor(supportedAlgorithms: Set<JWSAlgorithm>): JWSSignerFactory {
    require(supportedAlgorithms.isNotEmpty())
    val default = DefaultJWSSignerFactory()
    require(default.supportedJWSAlgorithms().containsAll(supportedAlgorithms)) {
        "There algorithms not supported. You can define at most ${default.supportedJWSAlgorithms()}"
    }
    return object : JWSSignerFactory by default {
        override fun supportedJWSAlgorithms(): MutableSet<JWSAlgorithm> = supportedAlgorithms.toMutableSet()
    }
}
