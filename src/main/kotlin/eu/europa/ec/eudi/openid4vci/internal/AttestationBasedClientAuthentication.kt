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
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.request.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URL
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.time.Duration

/**
 * Default implementation of [ClientAttestationPoPJWTBuilder]
 * Populates only the mandatory claims : `iss`, `exp`, `jit`, `aud` and the optional `iat`
 * In regard to JOSE header, only `alg` claim is being populated
 */
internal object DefaultClientAttestationPopJWTBuilder : ClientAttestationPoPJWTBuilder {

    override fun buildClientAttestationPoPJWT(
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

internal fun JsonObject.cnfJwk(): JWK? {
    return this["jwk"]?.let {
        val jsonString = Json.encodeToString(it)
        JWK.parse(jsonString)
    }
}

internal fun Map<String, Any?>.toJsonObject(): JsonObject {
    val jsonString = JSONObjectUtils.toJSONString(this)
    return Json.decodeFromString(jsonString)
}
fun JWTClaimsSet.cnf(): JsonObject? {
    return getJSONObjectClaim("cnf")?.toJsonObject()
}

/**
 * Adds header `DPoP` on the request under construction,  utilizing the passed [DPoPJwtFactory]
 */
internal fun HttpRequestBuilder.clientAttestationAndPoP(
    clientAttestationJWT: ClientAttestationJWT,
    clientAttestationPoPJWT: ClientAttestationPoPJWT,
) {
    header("OAuth-Client-Attestation", clientAttestationJWT.jwt.serialize())
    header("OAuth-Client-Attestation-PoP", clientAttestationPoPJWT.jwt.serialize())
}

//
// TO BE REMOVED
//
//

//
// Validation of ClientAttestationJWT
//
// TODO Should this be included?
internal data class ClientAttestationClaims(
    val clientId: ClientId,
    val pubKey: JWK,
) {

    init {
        require(clientId.isNotBlank() && clientId.isNotEmpty()) { "clientId cannot be blank" }
        require(!pubKey.isPrivate) { "InstanceKey should be public" }
    }
}

// TODO Should this be included?
//  Perhaps needs to be removed.
//  Also, remove ClientAttestationClaims
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
                expectedClaims: ClientAttestationClaims,
                issuer: String,
            ): ClaimsSetVerifier {
                val exactMatchClaims = JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(expectedClaims.clientId)
                    .claim("cnf", cnf(expectedClaims.pubKey.toPublicJWK()))
                    .build()
                return ClaimsSetVerifier(clock, exactMatchClaims)
            }
        }
    }

    fun create(
        clock: Clock,
        expectedClaims: ClientAttestationClaims,
        jwsTypeJWSVerifier: JOSEObjectTypeVerifier<SecurityContext> = DefaultJOSEObjectTypeVerifier.JWT,
        issuer: String,
        issuerKeySelector: JWSKeySelector<SecurityContext>,
    ): JWTProcessor<SecurityContext> = DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = jwsTypeJWSVerifier
        jwsKeySelector = issuerKeySelector
        jwtClaimsSetVerifier = ClaimsSetVerifier(clock, expectedClaims, issuer)
    }
}

// TODO Remove it
internal class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val duration: Duration,
    private val issuer: String,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val claims: ClientAttestationClaims,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        require(duration.isPositive()) { "Duration must be positive" }
        require(issuer.isNotBlank() && issuer.isNotEmpty()) { "issuer cannot be blank." }
        ClientAttestationPoPJWTSpec.requireIsAllowedAlgorithm(algorithm)
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
            issuer(issuer)
            subject(claims.clientId)
            claim("cnf", cnf(claims.pubKey.toPublicJWK()))
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
        }.build()
}

internal fun cnf(jwk: JWK): Map<String, Any> =
    mapOf("jwk" to jwk.toJSONObject())
