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
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.DefaultClientAttestationPopJWTBuilder
import eu.europa.ec.eudi.openid4vci.internal.cnfJwk
import java.net.URL
import java.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Qualification of a JWT that adheres to client attestation JWT
 * as described in Attestation-Based Client authentication
 * @param jwt the actual JWT
 */
data class ClientAttestationJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSigned()
    }

    val clientId: ClientId by lazy {
        checkNotNull(jwt.jwtClaimsSet.subject) { "Invalid JWT misses subject claim" }
    }

    val pubKey: JWK by lazy {
        val jwk = jwt.jwtClaimsSet.cnfJwk()
        checkNotNull(jwk) { "Invalid JWT misses cnf jwk" }
    }
}

/**
 * Qualification of a JWT that adheres to client attestation PoP JWT
 * as described in Attestation-Based Client authentication
 */
@JvmInline
value class ClientAttestationPoPJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSigned()
    }
}

/**
 * The information to be presented to authorization server token or PAR endpoint
 * to authenticate the wallet (as OAUTH2 client), as per Attestation-Based Client authentication
 *
 * @param clientAttestationJWT issued attestation JWT
 * @param clientAttestationPoPJWT proof of possession JWT
 */
data class JwtClientAttestation(
    val clientAttestationJWT: ClientAttestationJWT,
    val clientAttestationPoPJWT: ClientAttestationPoPJWT,
) {
    /**
     * Combines both the [clientAttestationJWT] & the [clientAttestationPoPJWT]
     * into a single string. JWTs are separated by a `~`
     */
    fun serialize(): String {
        val jwt = clientAttestationJWT.jwt.serialize()
        val pop = clientAttestationPoPJWT.jwt.serialize()
        return "$jwt~$pop"
    }
}

//
// Issuance
//
/**
 * Client to be authenticated to the credential issuer
 * using Attestation-Based Client Authentication
 *
 * @param pubKey The wallet instance pub key. This key will be used to identify the wallet
 * to a specific credential issuer. Should not be re-used.
 */
data class ClientAttestationIssuerRequest(
    val id: ClientId,
    val pubKey: JWK,
) {

    init {
        require(id.isNotBlank() && id.isNotEmpty())
        require(!pubKey.isPrivate) { "InstanceKey should be public" }
    }
}

/**
 * A function for issuing a [ClientAttestationJWT]
 */
fun interface ClientAttestationIssuer {

    /**
     * Issues a [ClientAttestationJWT] for the wallet
     *
     * @param request the wallet's data to be signed by the issuer
     */
    suspend fun issue(request: ClientAttestationIssuerRequest): ClientAttestationJWT
}

data class ClientAttestationPoPJWTSpec(
    val signingAlgorithm: JWSAlgorithm,
    val duration: Duration = 5.minutes,
    val typ: String? = null,
    val jwsSigner: JWSSigner,
) {
    init {
        requireIsAllowedAlgorithm(signingAlgorithm)
        require(duration.isPositive()) { "popJwtDuration must be positive" }
    }

    companion object {
        /**
         * [ECDSASigner.SUPPORTED_ALGORITHMS] & [RSASSASigner.SUPPORTED_ALGORITHMS]
         */
        val DefaultSupportedSigningAlgorithms =
            ECDSASigner.SUPPORTED_ALGORITHMS + RSASSASigner.SUPPORTED_ALGORITHMS

        internal fun requireIsAllowedAlgorithm(alg: JWSAlgorithm) =
            require(!alg.isMACSigning()) { "MAC signing algorithm not allowed" }

        private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS
    }
}

/**
 * A function for building a [ClientAttestationPoPJWT]
 */
fun interface ClientAttestationPoPJWTBuilder {

    /**
     * Builds a PoP JWT
     *
     * @param clock wallet's clock
     * @param authServerId the issuer claim of the OAUTH2/OIDC server to which
     * the attestation will be presented for authentication.
     *
     * @return the PoP JWT
     */
    suspend fun buildClientAttestationPoPJWT(
        clock: Clock,
        client: Client.Attested,
        authServerId: URL,
    ): ClientAttestationPoPJWT
}

fun interface ClientAttestationBuilder {

    suspend fun clientAttestation(): JwtClientAttestation

    companion object {

        operator fun invoke(
            clock: Clock,
            client: Client.Attested,
            authServerId: URL,
            clientAttestationPoPJWTBuilder: ClientAttestationPoPJWTBuilder = DefaultClientAttestationPopJWTBuilder,
        ): ClientAttestationBuilder =
            ClientAttestationBuilder {
                val popJwt = clientAttestationPoPJWTBuilder.buildClientAttestationPoPJWT(clock, client, authServerId)
                JwtClientAttestation(client.jwt, popJwt)
            }

        operator fun invoke(
            clock: Clock,
            client: Client,
            authServerId: URL?,
        ): ClientAttestationBuilder? = when (client) {
            is Client.Attested -> {
                requireNotNull(authServerId) {
                    "In case of attestation-based client authentication, authServerId is required"
                }
                invoke(clock, client, authServerId)
            }
            is Client.Public -> null
        }
    }
}

private fun SignedJWT.ensureSigned() {
    check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
}
