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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.JWKJsonObjectSerializer
import eu.europa.ec.eudi.openid4vci.internal.KeyAttestationJWTSerializer
import eu.europa.ec.eudi.openid4vci.internal.URLSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL

@ConsistentCopyVisibility
@Serializable(with = KeyAttestationJWTSerializer::class)
data class KeyAttestationJWT private constructor(val jwt: String, val header: JWSHeader, val claimsSet: KeyAttestationJWTClaims) {
    val attestedKeys: List<JWK> get() = claimsSet.attestedKeys

    companion object {
        operator fun invoke(jwt: String): KeyAttestationJWT = invoke(SignedJWT.parse(jwt))

        operator fun invoke(jwt: SignedJWT): KeyAttestationJWT {
            jwt.ensureType(JOSEObjectType(OpenId4VCISpec.KEY_ATTESTATION_JWT_TYPE))
            jwt.ensureSignedOrVerified()
            jwt.ensureSignedWithAllowedAlgorithm(TS3.WALLET_INSTANCE_ATTESTATION_ALLOWED_SIGNATURE_ALGORITHMS)
            val claimsSet = jwt.ensureValidClaimsSet<KeyAttestationJWTClaims>()
            return KeyAttestationJWT(jwt.serialize(), jwt.header, claimsSet)
        }
    }
}

fun KeyAttestationJWT.serialize(): String = jwt

typealias AttestedKeys = List<
    @Serializable(with = JWKJsonObjectSerializer::class)
    JWK,
    >

@Serializable
data class KeyAttestationJWTClaims(
    @Required @SerialName(RFC7519.ISSUED_AT) val issuedAt: InstantAsEpochSecond,
    @Required @SerialName(RFC7519.EXPIRATION_TIME) val expiresAt: InstantAsEpochSecond,
    @Required @SerialName(OpenId4VCISpec.ATTESTED_KEYS) val attestedKeys: AttestedKeys,
    @Required @SerialName(OpenId4VCISpec.KEY_STORAGE) val keyStorage: List<AttackPotentialResistance>,
    @Required @SerialName(OpenId4VCISpec.USER_AUTHENTICATION) val userAuthentication: List<AttackPotentialResistance>,
    @Required @SerialName(OpenId4VCISpec.CERTIFICATION) @Serializable(with = URLSerializer::class) val certification: URL,
    @SerialName(OpenId4VCISpec.NONCE) val nonce: Nonce? = null,
    @SerialName(TokenStatusListSpec.STATUS) val status: StatusClaim? = null,
    @Required @SerialName(TS3.KEY_STORAGE_STATUS) val keyStorageStatus: KeyStorageStatus,
) {
    init {
        require(attestedKeys.isNotEmpty()) { "attestedKeys must not be empty" }
        require(attestedKeys.none { it.isPrivate }) { "attestedKeys must all be public" }
        keyStorage.ensureLoAHigh { "keyStorage must contain [${AttackPotentialResistance.Iso18045High}]" }
        userAuthentication.ensureLoAHigh { "userAuthentication must contain [${AttackPotentialResistance.Iso18045High}]" }
    }

    companion object {
        /**
         * Enforces the TS3 requirement that `key_storage` and `user_authentication` must ensure LoA High, i.e. must contain `iso_18045_high`.
         */
        private fun List<AttackPotentialResistance>.ensureLoAHigh(error: () -> String) {
            require(AttackPotentialResistance.Iso18045High in this) { error() }
        }

        operator fun invoke(
            issuedAt: InstantAsEpochSecond,
            expiresAt: InstantAsEpochSecond,
            attestedKeys: AttestedKeys,
            certification: URL,
            nonce: Nonce?,
            status: StatusClaim?,
            keyStorageStatus: KeyStorageStatus,
        ): KeyAttestationJWTClaims = KeyAttestationJWTClaims(
            issuedAt = issuedAt,
            expiresAt = expiresAt,
            attestedKeys,
            keyStorage = listOf(AttackPotentialResistance.Iso18045High),
            userAuthentication = listOf(AttackPotentialResistance.Iso18045High),
            certification,
            nonce,
            status,
            keyStorageStatus,
        )
    }
}

@Serializable
data class KeyStorageStatus(
    @Required @SerialName(TokenStatusListSpec.STATUS) val status: StatusClaim,
    @Required @SerialName(RFC7519.EXPIRATION_TIME) val exp: InstantAsEpochSecond,
)

@JvmInline
@Serializable
value class AttackPotentialResistance(
    val value: String,
) {
    init {
        require(value.isNotBlank()) { "value must not be blank" }
    }

    override fun toString(): String = value

    companion object {
        val Iso18045High: AttackPotentialResistance =
            AttackPotentialResistance(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_HIGH)
        val Iso18045Moderate: AttackPotentialResistance =
            AttackPotentialResistance(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_MODERATE)
        val Iso18045EnhancedBasic: AttackPotentialResistance =
            AttackPotentialResistance(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_ENHANCED_BASIC)
        val Iso18045Basic: AttackPotentialResistance =
            AttackPotentialResistance(OpenId4VCISpec.ATTACK_POTENTIAL_RESISTANCE_ISO_18045_BASIC)
    }
}
