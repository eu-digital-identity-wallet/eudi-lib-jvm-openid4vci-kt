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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.JWTID
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.request.*
import kotlinx.serialization.json.put
import java.net.URL
import java.time.Clock

/**
 * Default implementation of [ClientAttestationPoPBuilder] per
 * [OAuth 2.0 Attestation-Based Client Authentication draft 07 §5.2](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-5.2).
 *
 * Creates a Client Attestation PoP JWT signed with [signer].
 *
 * **JWT header:** `alg` (set by [JwtSigner]) and
 * `typ = oauth-client-attestation-pop+jwt` ([AttestationBasedClientAuthenticationSpec.ATTESTATION_POP_JWT_TYPE]).
 *
 * **JWT claims:**
 * - Mandatory: `iss` ([clientId]), `aud` ([authorizationServerId]), `jti` (random UUID), `iat` ([clock] now)
 * - Optional: `nbf` (set to now), `challenge` (caller-supplied [Nonce], if provided)
 *
 * No `exp` claim is set — §5.2 does not define it for PoP JWTs; freshness is via `iat`/`challenge` window.
 */
internal class ClientAttestationPoPBuilder(
    private val clock: Clock,
    private val clientId: ClientId,
    private val authorizationServerId: URL,
    private val signer: Signer<JWK>,
) {

    suspend fun attestationPoPJWT(challenge: Nonce?): ClientAttestationPoPJWT {
        val now = clock.instant()
        val claimSet = ClientAttestationPOPClaims(
            issuer = clientId,
            audience = authorizationServerId,
            jwtId = JwtId(JWTID().value),
            issuedAt = now,
            challenge = challenge,
            notBefore = now,
        )
        val signedJwt = signer.use { signOperation ->
            JwtSigner<ClientAttestationPOPClaims, JWK>(
                signOperation = signOperation,
                algorithm = signer.javaAlgorithm.toJoseAlg(),
                customizeHeader = {
                    put(RFC7519.TYPE, AttestationBasedClientAuthenticationSpec.ATTESTATION_POP_JWT_TYPE)
                },
            ).sign(claimSet)
        }
        return ClientAttestationPoPJWT(SignedJWT.parse(signedJwt))
    }
}

internal fun HttpRequestBuilder.clientAttestationHeaders(
    clientAttestation: ClientAttestation,
) {
    val (attestation, pop) = clientAttestation
    header(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_HEADER, attestation.value)
    header(AttestationBasedClientAuthenticationSpec.CLIENT_ATTESTATION_POP_HEADER, pop.jwt.serialize())
}
