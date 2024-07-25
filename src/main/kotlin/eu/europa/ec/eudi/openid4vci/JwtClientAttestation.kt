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
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTProcessor
import eu.europa.ec.eudi.openid4vci.ClientAttestationBuilder.Companion.invoke
import eu.europa.ec.eudi.openid4vci.internal.DefaultClientAttestationPopJWTBuilder
import eu.europa.ec.eudi.openid4vci.internal.cnf
import eu.europa.ec.eudi.openid4vci.internal.cnfJwk
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import java.net.URL
import java.time.Clock
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Asserts the security mechanism the Wallet uses to manage the private key associated
 * with the public key given in the cnf claim.
 * This mechanism is based on the capabilities of the execution environment of the Wallet,
 * this might be a secure element (in case of a wallet residing on a smartphone)
 * or a Cloud-HSM (in case of a cloud Wallet)
 */
@Serializable
enum class KeyType {
    /**
     * Wallet uses software-based key management
     */
    @SerialName("software")
    Software,

    /**
     * Wallet uses hardware-based key management
     */
    @SerialName("hardware")
    Hardware,

    /**
     * Wallet uses the Trusted Execution Environment for key management
     */
    @SerialName("tee")
    TEE,

    /**
     * Wallet uses the Secure Enclave for key management
     */
    @SerialName("secure_enclave")
    SecureEnclave,

    /**
     * Wallet uses the Strongbox for key management
     */
    @SerialName("strong_box")
    StrongBox,

    /**
     * Wallet uses a Secure Element for key management
     */
    @SerialName("secure_element")
    SecureElement,

    /**
     * Wallet uses Hardware Security Module (HSM)
     */
    @SerialName("hsm")
    HSM,
}

/**
 *  Asserts the security mechanism the Wallet uses to authenticate the user
 *  to authorize access to the private key associated with the public key given in the cnf claim.
 *
 */
@Serializable
enum class UserAuthentication {
    /**
     * The key usage is authorized by the mobile operating system using a biometric factor
     */
    @SerialName("system_biometry")
    SystemBiometry,

    /**
     * The key usage is authorized by the mobile operating system using personal identification number (PIN).
     */
    @SerialName("system_pin")
    SystemPin,

    /**
     * The key usage is authorized by the Wallet using a biometric factor.
     */
    @SerialName("internal_biometry")
    InternalBiometry,

    /**
     * The key usage is authorized by the Wallet using PIN.
     */
    @SerialName("internal_pin")
    InternalPin,

    /**
     * The key usage is authorized by the secure element managing the key itself using PIN
     */
    @SerialName("secure_element_pin")
    SecureElementPin,
}

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

    val cnf: JsonObject by lazy {
        checkNotNull(jwt.jwtClaimsSet.cnf()) { "Invalid JWT misses cnf claim" }
    }
    val pubKey: JWK by lazy {
        checkNotNull(cnf.cnfJwk()) { "Invalid JWT misses jwk claim from cnf" }
    }

    /**
     * Asserts the security mechanism the Wallet uses to manage the private key associated
     * with the public key given in the cnf claim.
     */
    val keyType: KeyType?
        get() = cnf["key_type"]?.let(Json::decodeFromJsonElement)

    /**
     * Asserts the security mechanism the Wallet uses to authenticate the user
     * to authorize access to the private key associated with the public key given in the cnf claim.
     */
    val userAuthentication: UserAuthentication?
        get() = cnf["user_authentication"]?.let(Json::decodeFromJsonElement)

    val aal: String?
        get() = jwt.jwtClaimsSet.getStringClaim("aal")
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
// Validation of ClientAttestationJWT
//

data class ClientAttestationClaims(
    val clientId: ClientId,
    val pubKey: JWK,
) {

    init {
        require(clientId.isNotBlank() && clientId.isNotEmpty()) { "clientId cannot be blank" }
        require(!pubKey.isPrivate) { "InstanceKey should be public" }
    }
}

object ClientAttestationJWTProcessorFactory {

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

//
// Creation of Client Attestation
//

/**
 * A function for creating a [JwtClientAttestation]
 *
 * An instance may be obtained via [invoke]
 */
fun interface ClientAttestationBuilder {

    suspend fun clientAttestation(): JwtClientAttestation

    companion object {

        /**
         * Creates a builder which assumes that wallet has already obtained [ClientAttestationJWT],
         * that it is of type [Client.Attested]
         *
         * @param clock wallet's clock
         * @param client wallet which has already obtained [ClientAttestationJWT]
         * @param authServerId the URL of the authorization server (issuer of authorization server metadata) to
         * which the [JwtClientAttestation] will be presented.
         * It will be used to populate the aud claim of the [ClientAttestationPoPJWT]
         * @param clientAttestationPoPJWTBuilder the builder of the [ClientAttestationPoPJWT].
         * If not specified defaults to [DefaultClientAttestationPopJWTBuilder]
         *
         * @return a builder as described above
         */
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

        internal operator fun invoke(
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
