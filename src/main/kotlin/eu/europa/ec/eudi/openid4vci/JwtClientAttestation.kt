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
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.DefaultClientAttestationPopBuilder
import eu.europa.ec.eudi.openid4vci.internal.SelfAttestedIssuer
import eu.europa.ec.eudi.openid4vci.internal.SelfAttestedIssuer.Companion.DefaultSupportedSigningAlgorithms
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.Clock
import kotlin.time.Duration

/**
 * Qualification of a JWT that adheres to client attestation JWT
 * as described in Attestation-Based Client authentication
 * @param jwt the actual JWT
 */
@JvmInline
value class ClientAttestationJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSigned()
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

/**
 * A function for issuing a [ClientAttestationJWT]
 */
fun interface ClientAttestationIssuer {

    /**
     * Issues a [ClientAttestationJWT] for the wallet
     *
     * @param clock wallet's clock. Can be used to verify [ClientAttestationJWT]
     * @param client the wallet's data to be signed by the issuer
     */
    suspend fun issue(clock: Clock, client: Client.Attested): ClientAttestationJWT

    companion object {

        /**
         * Factory method for creating a [ClientAttestationIssuer] where the wallet itself
         * signs the [ClientAttestationJWT] (without a back-end service)
         *
         * @param supportedSigningAlgorithms the algorithms to be used to sign the [ClientAttestationJWT]
         * if not provided defaults to [DefaultSupportedSigningAlgorithms]. Caller should make sure that
         * the provided algorithms are compatible with [Client.Attested.instanceKey]
         * @param attestationDuration how long the attestation could live. It will be used to calculate
         * the expiration time of the [ClientAttestationJWT]
         * @param headerCustomization possible customization of the JOSE header of the [ClientAttestationJWT].
         * If not provided, only the `alg` claim will be included.
         *
         * @return an issuer as described above
         */
        fun selfAttested(
            supportedSigningAlgorithms: Set<JWSAlgorithm> = DefaultSupportedSigningAlgorithms,
            attestationDuration: Duration,
            headerCustomization: JWSHeader.Builder.() -> Unit = {},
        ): ClientAttestationIssuer = SelfAttestedIssuer(
            supportedSigningAlgorithms,
            attestationDuration,
            headerCustomization,
        )
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
     * @param client the wallet's data
     * @param authServerId the issuer claim of the OAUTH2/OIDC server to which
     * the attestation will be presented for authentication.
     * @param duration the time to live of the PoP JWT. It will be used to calculate
     * the expiration time (`exp` claim)
     * @param jwtId an option identifier to be included a `jit` claim. If not provided,
     * a random value will be used

     * @return the PoP JWT
     */
    suspend fun build(
        clock: Clock,
        client: Client.Attested,
        authServerId: String,
        duration: Duration,
        jwtId: String?,
    ): ClientAttestationPoPJWT

    companion object {
        /**
         * Default implementation
         */
        val Default: ClientAttestationPoPJWTBuilder = DefaultClientAttestationPopBuilder
    }
}

/**
 * Issues [JwtClientAttestation] using an [attestationIssuer] & [popJwtBuilder]
 *
 * @param attestationIssuer a way of issuing [ClientAttestationJWT]
 * @param popJwtBuilder a way of building a [ClientAttestationPoPJWT]
 * @param popJwtDuration the duration of the [ClientAttestationPoPJWT]
 * @param clientAttestationJwt a [ClientAttestationJWT] that wallet may have issued before, by other means.
 * If not provided, or if it is expired, a new [ClientAttestationJWT] will be issued using [attestationIssuer]
 */
class JwtClientAssertionIssuer(
    private val clock: Clock,
    private val attestationIssuer: ClientAttestationIssuer,
    private val popJwtBuilder: ClientAttestationPoPJWTBuilder,
    private val popJwtDuration: Duration,
    private var clientAttestationJwt: ClientAttestationJWT? = null,
) {

    private val mutex = Mutex()

    /**
     * Issues a [JwtClientAttestation]
     * A new [ClientAttestationJWT] will be provisioned, in case if [clientAttestationJwt] has not been
     * provided or if it is expired
     * @param client the wallet's data to be signed by the issuer
     * @param authServerIssuer the authorization server to which the wallet will present the [JwtClientAttestation].
     * It is used to populate the audience claim of the [ClientAttestationPoPJWT]
     */
    suspend fun issue(
        client: Client.Attested,
        authServerIssuer: String,
    ): JwtClientAttestation = coroutineScope {
        val attestationJwt = async { issueIfNeededAttestationJwt(client) }
        val attestationPoPJwt = async { buildPopJwt(client, authServerIssuer) }

        JwtClientAttestation(attestationJwt.await(), attestationPoPJwt.await())
    }

    private suspend fun issueIfNeededAttestationJwt(client: Client.Attested): ClientAttestationJWT =
        mutex.withLock {
            val current = clientAttestationJwt
            if (current == null || current.jwt.isExpired()) {
                clientAttestationJwt = attestationIssuer.issue(clock, client)
            }
            checkNotNull(clientAttestationJwt)
        }

    private suspend fun buildPopJwt(client: Client.Attested, authServerIssuer: String): ClientAttestationPoPJWT =
        popJwtBuilder.build(clock, client, authServerIssuer, popJwtDuration, null)

    // TODO this needs to take into account clock skew
    private fun SignedJWT.isExpired(): Boolean {
        val exp = jwtClaimsSet.expirationTime?.toInstant() ?: error("Missing exp claim")
        val now = clock.instant()
        return !exp.isAfter(now)
    }
}

private fun SignedJWT.ensureSigned() {
    check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Provided JWT is not signed"
    }
}
