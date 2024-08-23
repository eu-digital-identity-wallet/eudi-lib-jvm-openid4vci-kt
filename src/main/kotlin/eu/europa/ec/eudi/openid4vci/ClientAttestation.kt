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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.DefaultClientAttestationPoPBuilder
import eu.europa.ec.eudi.openid4vci.internal.cnf
import eu.europa.ec.eudi.openid4vci.internal.cnfJwk
import kotlinx.serialization.json.JsonObject
import java.net.URL
import java.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * These JWTs are transmitted via HTTP headers in an HTTP request from a Client Instance
 * to an Authorization Server or Resource Server. The primary purpose of these headers is
 * to authenticate the Client Instance
 */
typealias ClientAttestation = Pair<ClientAttestationJWT, ClientAttestationPoPJWT>

/**
 * Qualification of a JWT that adheres to client attestation JWT
 * as described in Attestation-Based Client authentication
 *
 * @param jwt A JSON Web Token (JWT) generated by the client backend
 * which is bound to a key managed by a Client Instance which can then
 * be used by the instance for client authentication
 */
data class ClientAttestationJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSignedNotMAC()
        requireNotNull(jwt.jwtClaimsSet.subject) { "Invalid Attestation JWT. Misses subject claim" }
        val cnf = requireNotNull(jwt.jwtClaimsSet.cnf()) { "Invalid Attestation JWT. Misses cnf claim" }
        requireNotNull(cnf.cnfJwk()) { "Invalid Attestation JWT. Misses jwk claim from cnf" }
        requireNotNull(jwt.jwtClaimsSet.expirationTime) { "Invalid Attestation JWT. Misses exp claim" }
    }

    val clientId: ClientId
        get() = jwt.jwtClaimsSet.subject
    val cnf: JsonObject by lazy { checkNotNull(jwt.jwtClaimsSet.cnf()) }
    val pubKey: JWK by lazy { checkNotNull(cnf.cnfJwk()) }
}

/**
 * Qualification of a JWT that adheres to client attestation PoP JWT
 * as described in Attestation-Based Client authentication
 *
 * @param jwt A Proof of Possession generated by the Client Instance
 * using the key that the Client Attestation JWT is bound to.
 */
@JvmInline
value class ClientAttestationPoPJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSignedNotMAC()
        requireNotNull(jwt.jwtClaimsSet.issuer) { "Invalid PoP JWT. Misses iss claim" }
        requireNotNull(jwt.jwtClaimsSet.expirationTime) { "Invalid PoP JWT. Misses exp claim" }
        requireNotNull(jwt.jwtClaimsSet.jwtid) { "Invalid PoP JWT. Misses jti claim" }
        require(!jwt.jwtClaimsSet.audience.isNullOrEmpty()) { "Invalid PoP JWT. Misses aud claim" }
    }
}

//
// Creation of ClientAttestationPoPJWT
//

data class ClientAttestationPoPJWTSpec(
    val signingAlgorithm: JWSAlgorithm,
    val duration: Duration = 5.minutes,
    val typ: String? = null,
    val jwsSigner: JWSSigner,
) {
    init {
        requireIsNotMAC(signingAlgorithm)
        require(duration.isPositive()) { "popJwtDuration must be positive" }
    }
}

/**
 * A function for building a [ClientAttestationPoPJWT]
 * in the context of a [Client.Attested] client
 */
fun interface ClientAttestationPoPBuilder {

    /**
     * Builds a PoP JWT
     *
     * @param clock wallet's clock
     * @param authServerId the issuer claim of the OAUTH2/OIDC server to which
     * the attestation will be presented for authentication.
     * @receiver the client for which to create the PoP
     *
     * @return the PoP JWT
     */
    fun Client.Attested.attestationPoPJWT(clock: Clock, authServerId: URL): ClientAttestationPoPJWT

    companion object {
        val Default: ClientAttestationPoPBuilder = DefaultClientAttestationPoPBuilder
    }
}

private fun SignedJWT.ensureSignedNotMAC() {
    check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
    val alg = requireNotNull(header.algorithm) { "Invalid JWT misses header alg" }
    requireIsNotMAC(alg)
}

internal fun requireIsNotMAC(alg: JWSAlgorithm) =
    require(!alg.isMACSigning()) { "MAC signing algorithm not allowed" }

private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS
