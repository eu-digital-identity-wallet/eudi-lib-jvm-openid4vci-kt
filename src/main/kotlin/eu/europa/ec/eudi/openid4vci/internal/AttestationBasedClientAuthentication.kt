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

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.request.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.put
import java.net.URL
import java.time.Clock

/**
 * Default implementation of [ClientAttestationPoPBuilder]
 * Populates only the mandatory claims : `iss`, `exp`, `jit`, `aud` and the optional `iat`
 * In regard to JOSE header, only `alg` claim is being populated
 */
internal object DefaultClientAttestationPoPBuilder : ClientAttestationPoPBuilder {

    override suspend fun ClientAuthentication.AttestationBased.attestationPoPJWT(
        clock: Clock,
        authorizationServerId: URL,
        challenge: Nonce?,
    ): ClientAttestationPoPJWT {
        val now = clock.instant()
        val claimSet = ClientAttestationPOPClaims(
            issuer = id,
            audience = authorizationServerId,
            jwtId = JwtId(JWTID().value),
            issuedAt = now,
            challenge = challenge,
            notBefore = now,
        )
        val signedJwt = popJwtSpec.signer.use { signOperation ->
            JwtSigner<ClientAttestationPOPClaims, JWK>(
                signOperation = signOperation,
                algorithm = popJwtSpec.signer.javaAlgorithm.toJoseAlg(),
                customizeHeader = {
                    put(RFC7519.TYPE, AttestationBasedClientAuthenticationSpec.ATTESTATION_POP_JWT_TYPE)
                },
            ).sign(claimSet)
        }
        return ClientAttestationPoPJWT(SignedJWT.parse(signedJwt))
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
    header(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_HEADER, attestation.jwt.serialize())
    header(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_POP_HEADER, pop.jwt.serialize())
}

internal suspend fun OpenId4VCIConfig.generateClientAttestationIfNeeded(
    authorizationServerId: URL,
    challenge: Nonce?,
): ClientAttestation? =
    clientAttestationPoPBuilder.generateClientAttestationIfNeeded(
        clock,
        clientAuthentication,
        authorizationServerId,
        challenge,
    )

internal suspend fun DeferredIssuerConfig.generateClientAttestationIfNeeded(challenge: Nonce?): ClientAttestation? =
    clientAttestationPoPBuilder.generateClientAttestationIfNeeded(clock, clientAuthentication, authorizationServerId, challenge)

private suspend fun ClientAttestationPoPBuilder.generateClientAttestationIfNeeded(
    clock: Clock,
    clientAuthentication: ClientAuthentication,
    authorizationServerId: URL,
    challenge: Nonce?,
): ClientAttestation? =
    when (clientAuthentication) {
        is ClientAuthentication.AttestationBased -> {
            val clientAttestationPoPJwt = clientAuthentication.attestationPoPJWT(clock, authorizationServerId, challenge)
            clientAuthentication.attestationJWT to clientAttestationPoPJwt
        }
        else -> null
    }
