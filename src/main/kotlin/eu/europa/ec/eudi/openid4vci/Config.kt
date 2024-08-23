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
import com.nimbusds.jose.jwk.Curve
import java.net.URI
import java.time.Clock

typealias ClientId = String

/**
 * Wallet's OAUTH2 client view
 */
sealed interface Client : java.io.Serializable {
    /**
     * The client_id of the Wallet, issued when interacting with a credential issuer
     */
    val id: ClientId

    /**
     * Public Client
     */
    data class Public(override val id: ClientId) : Client

    data class Attested(
        val attestation: ClientAttestation,
        val popJwtSpec: ClientAttestationPoPJWTSpec,
    ) : Client {
        init {
            val id = attestation.clientId
            require(id.isNotBlank() && id.isNotEmpty())
            val pubKey = attestation.pubKey
            require(!pubKey.isPrivate) { "InstanceKey should be public" }
        }

        override val id: ClientId = attestation.clientId
    }
}

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param client the OAUTH2 client kind of the wallet
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 * @param keyGenerationConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param credentialResponseEncryptionPolicy Wallet's policy for Credential Response encryption
 * @param authorizeIssuanceConfig Instruction on how to assemble the authorization request. If scopes are supported
 * by the credential issuer and [AuthorizeIssuanceConfig.FAVOR_SCOPES] is selected then scopes will be used.
 * Otherwise, authorization details (RAR)
 * @param dPoPSigner a signer that if provided will enable the use of DPoP JWT
 * @param clientAttestationPoPBuilder a way to build a [ClientAttestationPoP]
 * @param parUsage whether to use PAR in case of authorization code grant
 * @param clock Wallet's clock
 */
data class OpenId4VCIConfig(
    val client: Client,
    val authFlowRedirectionURI: URI,
    val keyGenerationConfig: KeyGenerationConfig,
    val credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
    val dPoPSigner: PopSigner.Jwt? = null,
    val clientAttestationPoPBuilder: ClientAttestationPoPBuilder = ClientAttestationPoPBuilder.Default,
    val parUsage: ParUsage = ParUsage.IfSupported,
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
            requireNotNull(clientAttestationPoPBuilder) {
                "Client attestation PoP builder is required"
            }
        }
    }

    @Deprecated(
        message = "Deprecated in favor of openId4VCIConfig client.id",
        replaceWith = ReplaceWith("client.id"),
    )
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
