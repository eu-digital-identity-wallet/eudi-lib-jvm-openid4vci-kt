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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import java.net.URI
import java.time.Clock

typealias ClientId = String

/**
 * Wallet's OAUTH2 client view
 */
sealed interface Client {
    /**
     * The client_id of the Wallet, issued when interacting with a credential issuer
     */
    val id: ClientId

    /**
     * Public Client
     */
    data class Public(override val id: ClientId) : Client

    /**
     * Client to be authenticated to the credential issuer
     * using Attestation-Based Client Authentication
     *
     * @param instanceKey The wallet instance key (pair). This key will be used to identify the wallet
     * to a specific credential issuer. Should not be re-used.
     * @param popSigningAlgorithm the algorithm to be used to sign the [ClientAttestationPoPJWT]
     */
    data class Attested(
        override val id: ClientId,
        val instanceKey: JWK,
        val popSigningAlgorithm: JWSAlgorithm,
    ) : Client {
        init {
            require(id.isNotBlank() && id.isNotEmpty())
            require(instanceKey.isPrivate) { "Instance key must be private" }
            requireIsAllowedAlgorithm(popSigningAlgorithm)
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
}

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param client  The wallet as OAUTH2 client during issuance
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 * @param keyGenerationConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param credentialResponseEncryptionPolicy Wallet's policy for Credential Response encryption
 * @param authorizeIssuanceConfig Instruction on how to assemble the authorization request. If scopes are supported
 * by the credential issuer and [AuthorizeIssuanceConfig.FAVOR_SCOPES] is selected then scopes will be used.
 * Otherwise, authorization details (RAR)
 * @param dPoPSigner a signer that if provided will enable the use of DPoP JWT
 * @param parUsage whether to use PAR in case of authorization code grant
 * @param jwtClientAssertionIssuer a function for issuing [JwtClientAssertionIssuer]. Required in case
 * [client] is [Client.Attested]
 * @param clock Wallet's clock
 */
data class OpenId4VCIConfig(
    val client: Client,
    val authFlowRedirectionURI: URI,
    val keyGenerationConfig: KeyGenerationConfig,
    val credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
    val dPoPSigner: PopSigner.Jwt? = null,
    val parUsage: ParUsage = ParUsage.IfSupported,
    val jwtClientAssertionIssuer: JwtClientAssertionIssuer? = null,
    val clock: Clock = Clock.systemDefaultZone(),

) {

    init {
        if (null != dPoPSigner) {
            val key = dPoPSigner.bindingKey
            require(key is JwtBindingKey.Jwk) {
                "Only JWK can be used with DPoP Proof signer"
            }
            require(!key.jwk.isPrivate) {
                "JWK in binding key must be public"
            }
        }
        if (client is Client.Attested) {
            requireNotNull(jwtClientAssertionIssuer) {
                "jwtClientAssertionIssuer issuer must be configured"
            }
        }
    }

    @Deprecated(message = "Deprecated", replaceWith = ReplaceWith("client.id"))
    val clientId: ClientId
        get() = client.id
}

/**
 * Wallet's policy in regard to using PAR, during a authorization code grant.
 * - [IfSupported]: If authorization server advertises PAR endpoint it will be used. Otherwise, falls back
 *   to usual authorization code flow
 * - [Never]: Disables PAR. Wallet will use the usual authorization code flow
 * - [Required]: Wallet always will place PAR request, regardless what if authorization server advertises the PAR
 *   endpoint. If PAR endpoint is not being advertised, the issuance will fail.
 */
enum class ParUsage {
    IfSupported,
    Never,
    Required,
}

/**
 * Wallet's policy concerning Credential Response encryption.
 */
enum class CredentialResponseEncryptionPolicy {

    /**
     * The Wallet requires Credential Responses to be encrypted.
     */
    REQUIRED,

    /**
     * The Wallet supports encrypted Credential Responses,
     * but can accept unencrypted Credential Responses as well.
     */
    SUPPORTED,
}

data class KeyGenerationConfig(
    val ecConfig: EcConfig?,
    val rsaConfig: RsaConfig?,
) {
    companion object {
        operator fun invoke(
            ecKeyCurve: Curve,
            rcaKeySize: Int,
        ): KeyGenerationConfig = KeyGenerationConfig(EcConfig(ecKeyCurve), RsaConfig(rcaKeySize))

        fun ecOnly(
            ecKeyCurve: Curve,
            supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.ECDH_ES.toList(),
        ): KeyGenerationConfig = KeyGenerationConfig(EcConfig(ecKeyCurve, supportedJWEAlgorithms), null)
    }
}

data class RsaConfig(
    val rcaKeySize: Int,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.RSA.toList(),
) {
    init {
        require(JWEAlgorithm.Family.RSA.containsAll(supportedJWEAlgorithms)) {
            "Provided algorithms that are not part of RSA family"
        }
    }
}

data class EcConfig(
    val ecKeyCurve: Curve,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = JWEAlgorithm.Family.ECDH_ES.toList(),
) {
    init {
        require(JWEAlgorithm.Family.ECDH_ES.containsAll(supportedJWEAlgorithms)) {
            "Provided algorithms that are not part of ECDH_ES family"
        }
    }
}

enum class AuthorizeIssuanceConfig {
    FAVOR_SCOPES,
    AUTHORIZATION_DETAILS,
}
