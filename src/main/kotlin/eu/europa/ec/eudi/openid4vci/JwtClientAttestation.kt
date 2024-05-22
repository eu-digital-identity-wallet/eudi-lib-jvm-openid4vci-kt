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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.DefaultClientAttestationPopBuilder
import eu.europa.ec.eudi.openid4vci.internal.SelfAttestedIssuer
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.time.Clock
import kotlin.time.Duration

@JvmInline
value class ClientAttestationJWT(val jwt: SignedJWT)

@JvmInline
value class ClientAttestationPoP(val jwt: SignedJWT)

data class JwtClientAttestation(
    val clientAttestationJWT: ClientAttestationJWT,
    val clientAttestationPoP: ClientAttestationPoP,
) {
    init {
        clientAttestationJWT.jwt.ensureSigned()
        clientAttestationPoP.jwt.ensureSigned()
    }

    fun serialize(): String = "${clientAttestationJWT.jwt.serialize()}~${clientAttestationPoP.jwt.serialize()}"

    companion object {
        private fun SignedJWT.ensureSigned() {
            check(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
                "Provided JWT is not signed"
            }
        }
    }
}

fun interface ClientAttestationIssuer {
    suspend fun issue(client: Client.Attested): ClientAttestationJWT

    companion object {

        fun selfAttested(
            clock: Clock,
            attestationDuration: Duration,
            typ: JOSEObjectType = JOSEObjectType.JWT,
            headerCustomization: JWSHeader.Builder.() -> Unit = {},
        ): ClientAttestationIssuer = SelfAttestedIssuer(clock, attestationDuration, typ, headerCustomization)
    }
}

fun interface ClientAttestationPoPBuilder {
    suspend fun issue(client: Client.Attested, authServerId: String): ClientAttestationPoP

    companion object {
        fun default(clock: Clock, duration: Duration): ClientAttestationPoPBuilder =
            DefaultClientAttestationPopBuilder(clock, duration)
    }
}

class JwtClientAssertionIssuer(
    private val clientAttestationIssuer: ClientAttestationIssuer,
    private val clientAttestationPoPBuilder: ClientAttestationPoPBuilder,
) {

    suspend fun issue(
        client: Client.Attested,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
    ): JwtClientAttestation = coroutineScope {
        val clientAttestationJwt = async { clientAttestationIssuer.issue(client) }
        val clientAttestationPoP =
            async { clientAttestationPoPBuilder.issue(client, authorizationServerMetadata.issuer.value) }
        JwtClientAttestation(clientAttestationJwt.await(), clientAttestationPoP.await())
    }
}
