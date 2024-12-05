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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Clock
import java.util.*
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

@Suppress("UNUSED")
internal fun selfSignedClient(
    clock: Clock = Clock.systemDefaultZone(),
    walletInstanceKey: ECKey,
    clientId: String,
    duration: Duration = 10.minutes,
    keyType: KeyType? = null,
    userAuthentication: UserAuthentication? = null,
    headerCustomization: JWSHeader.Builder.() -> Unit = {},
): Client.Attested {
    require(walletInstanceKey.curve == Curve.P_256)
    val algorithm = JWSAlgorithm.ES256
    val signer = DefaultJWSSignerFactory().createJWSSigner(walletInstanceKey, algorithm)
    val clientAttestationJWT = run {
        val claims = ClientAttestationClaims(
            issuer = clientId,
            clientId = clientId,
            cnf = Cnf(
                walletInstancePubKey = walletInstanceKey.toPublicJWK(),
                keyType = keyType,
                userAuthentication = userAuthentication,
            ),
        )
        val builder = ClientAttestationJwtBuilder(clock, duration, algorithm, signer, claims, headerCustomization)
        builder.build()
    }
    val popJwtSpec = ClientAttestationPoPJWTSpec(
        JWSAlgorithm.ES256,
        duration,
        jwsSigner = signer,
    )
    return Client.Attested(clientAttestationJWT, popJwtSpec)
}

/**
 * Asserts the security mechanism the Wallet uses to manage the private key associated
 * with the public key given in the cnf claim.
 * This mechanism is based on the capabilities of the execution environment of the Wallet,
 * this might be a secure element (in case of a wallet residing on a smartphone)
 * or a Cloud-HSM (in case of a cloud Wallet)
 */
@Suppress("UNUSED")
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
@Suppress("UNUSED")
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

data class Cnf(
    val walletInstancePubKey: JWK,
    val keyType: KeyType? = null,
    val userAuthentication: UserAuthentication? = null,
    val aal: String? = null,
) {
    init {
        require(!walletInstancePubKey.isPrivate) { "InstanceKey should be public" }
    }
}

data class ClientAttestationClaims(
    val issuer: String,
    val clientId: ClientId,
    val cnf: Cnf,
) {

    init {
        require(clientId.isNotBlank() && clientId.isNotEmpty()) { "clientId cannot be blank" }
    }
}

private class ClientAttestationJwtBuilder(
    private val clock: Clock,
    private val duration: Duration,
    private val algorithm: JWSAlgorithm,
    private val signer: JWSSigner,
    private val claims: ClientAttestationClaims,
    private val headerCustomization: JWSHeader.Builder.() -> Unit = {},
) {
    init {
        require(duration.isPositive()) { "Duration must be positive" }
        requireIsNotMAC(algorithm)
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
            headerCustomization()
            type(JOSEObjectType(TYPE))
        }.build()

    private fun claimSetForm(claims: ClientAttestationClaims): JWTClaimsSet =
        JWTClaimsSet.Builder().apply {
            val now = clock.instant()
            val exp = now.plusSeconds(duration.inWholeSeconds)
            issuer(claims.issuer)
            subject(claims.clientId)
            claim("cnf", cnf(claims.cnf))
            issueTime(Date.from(now))
            expirationTime(Date.from(exp))
        }.build()

    companion object {
        const val TYPE: String = "oauth-client-attestation+jwt"
        fun ecKey256(
            clock: Clock,
            duration: Duration,
            claims: ClientAttestationClaims,
            headerCustomization: JWSHeader.Builder.() -> Unit = {},
            privateKey: ECKey,
        ): ClientAttestationJwtBuilder {
            require(privateKey.curve == Curve.P_256)
            val algorithm = JWSAlgorithm.ES256
            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
            return ClientAttestationJwtBuilder(clock, duration, algorithm, signer, claims, headerCustomization)
        }
    }
}

private fun cnf(cnf: Cnf): Map<String, Any> =
    buildMap {
        put("jwt", cnf.walletInstancePubKey.toJSONObject())
        cnf.keyType?.let { put("key_type", Json.encodeToString(it)) }
        cnf.userAuthentication?.let { put("user_authentication", Json.encodeToString(it)) }
        cnf.aal?.let { put("aal", it) }
    }
