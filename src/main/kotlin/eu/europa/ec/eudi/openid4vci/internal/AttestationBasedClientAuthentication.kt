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
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.request.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URL
import java.time.Clock
import java.time.Instant
import java.util.*

/**
 * Default implementation of [ClientAttestationPoPBuilder]
 * Populates only the mandatory claims : `iss`, `exp`, `jit`, `aud` and the optional `iat`
 * In regard to JOSE header, only `alg` claim is being populated
 */
internal object DefaultClientAttestationPoPBuilder : ClientAttestationPoPBuilder {

    override fun Client.Attested.attestationPoPJWT(
        clock: Clock,
        authServerId: URL,
    ): ClientAttestationPoPJWT {
        val header = popJwtHeader()
        val claimSet = popJwtClaimSet(authServerId, clock.instant())
        val jwt = SignedJWT(header, claimSet).apply { sign(popJwtSpec.jwsSigner) }
        return ClientAttestationPoPJWT(jwt)
    }

    private fun Client.Attested.popJwtHeader(): JWSHeader =
        JWSHeader.Builder(popJwtSpec.signingAlgorithm).apply {
            type(JOSEObjectType(popJwtSpec.typ))
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

internal fun JWTClaimsSet.cnf(): JsonObject? {
    return getJSONObjectClaim("cnf")?.toJsonObject()
}

internal fun HttpRequestBuilder.clientAttestationHeaders(
    clientAttestation: ClientAttestation,
) {
    val (attestation, pop) = clientAttestation
    header("OAuth-Client-Attestation", attestation.jwt.serialize())
    header("OAuth-Client-Attestation-PoP", pop.jwt.serialize())
}

internal fun OpenId4VCIConfig.generateClientAttestationIfNeeded(
    authServerId: URL,
): ClientAttestation? =
    clientAttestationPoPBuilder.generateClientAttestationIfNeeded(clock, client, authServerId)

internal fun DeferredIssuerConfig.generateClientAttestationIfNeeded(): ClientAttestation? =
    clientAttestationPoPBuilder.generateClientAttestationIfNeeded(clock, client, authServerId)

private fun ClientAttestationPoPBuilder.generateClientAttestationIfNeeded(
    clock: Clock,
    client: Client,
    authServerId: URL,
): ClientAttestation? =
    when (client) {
        is Client.Attested -> client.attestationJWT to client.attestationPoPJWT(clock, authServerId)
        else -> null
    }
