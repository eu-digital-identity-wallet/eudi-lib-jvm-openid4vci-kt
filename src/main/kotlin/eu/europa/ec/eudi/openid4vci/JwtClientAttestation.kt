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

@JvmInline
value class ClientAttestationJWT(val jwt: SignedJWT) {
    init {
        jwt.ensureSigned()
    }
}

@JvmInline
value class ClientAttestationPoP(val jwt: SignedJWT) {
    init {
        jwt.ensureSigned()
    }
}

data class JwtClientAttestation(
    val clientAttestationJWT: ClientAttestationJWT,
    val clientAttestationPoP: ClientAttestationPoP,
) {
    fun serialize(): String {
        val jwt = clientAttestationJWT.jwt.serialize()
        val pop = clientAttestationPoP.jwt.serialize()
        return "$jwt~$pop"
    }
}

fun interface ClientAttestationIssuer {
    suspend fun issue(clock: Clock, client: Client.Attested): ClientAttestationJWT

    companion object {

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

fun interface ClientAttestationPoPBuilder {
    suspend fun build(clock: Clock, client: Client.Attested, authServerId: String): ClientAttestationPoP

    companion object {
        fun default(
            supportedSigningAlgorithms: Set<JWSAlgorithm> = DefaultSupportedSigningAlgorithms,
            duration: Duration,
        ): ClientAttestationPoPBuilder =
            DefaultClientAttestationPopBuilder(supportedSigningAlgorithms, duration)
    }
}

class JwtClientAssertionIssuer(
    private val clock: Clock,
    private val attestationIssuer: ClientAttestationIssuer,
    private val popBuilder: ClientAttestationPoPBuilder,
    private var clientAttestationJwt: ClientAttestationJWT? = null,
) {

    private val mutex = Mutex()

    suspend fun issue(
        client: Client.Attested,
        authServerIssuer: String,
    ): JwtClientAttestation = coroutineScope {
        val attestationJwt = async { issueIfNeededAttestationJwt(client) }
        val attestationPoP = async { buildPop(client, authServerIssuer) }

        JwtClientAttestation(attestationJwt.await(), attestationPoP.await())
    }

    private suspend fun issueIfNeededAttestationJwt(client: Client.Attested): ClientAttestationJWT =
        mutex.withLock {
            val current = clientAttestationJwt
            if (current == null || current.jwt.isExpired()) {
                clientAttestationJwt = attestationIssuer.issue(clock, client)
            }
            checkNotNull(clientAttestationJwt)
        }

    private suspend fun buildPop(client: Client.Attested, authServerIssuer: String): ClientAttestationPoP =
        popBuilder.build(clock, client, authServerIssuer)

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
