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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.ParUsage.*
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
        val attestationJWT: ClientAttestationJWT,
        val popJwtSpec: ClientAttestationPoPJWTSpec,
    ) : Client {
        init {
            val id = attestationJWT.clientId
            require(id.isNotBlank() && id.isNotEmpty())
            val pubKey = attestationJWT.pubKey
            require(!pubKey.isPrivate) { "InstanceKey should be public" }
        }

        override val id: ClientId = attestationJWT.clientId
    }
}

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param client the OAUTH2 client kind of the wallet
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 * @param encryptionSupportConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param authorizeIssuanceConfig Instruction on how to assemble the authorization request. If scopes are supported
 * by the credential issuer and [AuthorizeIssuanceConfig.FAVOR_SCOPES] is selected then scopes will be used.
 * Otherwise, authorization details (RAR)
 * @param dPoPSigner a signer that if provided will enable the use of DPoP JWT
 * @param clientAttestationPoPBuilder a way to build a [ClientAttestationPoPJWT]
 * @param parUsage whether to use PAR in case of authorization code grant
 * @param clock Wallet's clock
 * @param issuerMetadataPolicy policy concerning signed metadata usage
 */
data class OpenId4VCIConfig(
    val client: Client,
    val authFlowRedirectionURI: URI,
    val encryptionSupportConfig: EncryptionSupportConfig,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
    val dPoPSigner: Signer<JWK>? = null,
    val clientAttestationPoPBuilder: ClientAttestationPoPBuilder = ClientAttestationPoPBuilder.Default,
    val parUsage: ParUsage = ParUsage.IfSupported,
    val clock: Clock = Clock.systemDefaultZone(),
    val issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
) {

    constructor(
        clientId: ClientId,
        authFlowRedirectionURI: URI,
        encryptionSupportConfig: EncryptionSupportConfig,
        authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        dPoPSigner: Signer<JWK>? = null,
        clientAttestationPoPBuilder: ClientAttestationPoPBuilder = ClientAttestationPoPBuilder.Default,
        parUsage: ParUsage = ParUsage.IfSupported,
        clock: Clock = Clock.systemDefaultZone(),
        issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    ) : this(
        Client.Public(clientId),
        authFlowRedirectionURI,
        encryptionSupportConfig,
        authorizeIssuanceConfig,
        dPoPSigner,
        clientAttestationPoPBuilder,
        parUsage,
        clock,
        issuerMetadataPolicy,
    )

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

data class EncryptionSupportConfig(
    val compressionAlgorithms: List<CompressionAlgorithm>? = listOf(CompressionAlgorithm.DEF),
    val credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
    val ecConfig: EcConfig?,
    val rsaConfig: RsaConfig?,
    val supportedEncryptionMethods: List<EncryptionMethod> = ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS.toList(),
) {
    init {
        require(supportedEncryptionMethods.isNotEmpty()) { "At least one encryption method must be provided" }
        val unsupportedEncryptionMethods = supportedEncryptionMethods.filterNot { it in ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS }
        require(unsupportedEncryptionMethods.isEmpty()) {
            "Unsupported encryption methods: ${unsupportedEncryptionMethods.joinToString(", ") { it.name }}"
        }
        require(supportedEncryptionMethods.distinctBy { it.name }.size == supportedEncryptionMethods.size) {
            "supportedEncryptionMethods contains duplicate values"
        }
    }

    val supportedEncryptionAlgorithms: List<JWEAlgorithm> get() = buildList {
        ecConfig?.supportedJWEAlgorithms?.let { addAll(it) }
        rsaConfig?.supportedJWEAlgorithms?.let { addAll(it) }
    }

    companion object {
        operator fun invoke(
            ecKeyCurve: Curve,
            rcaKeySize: Int,
            credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
        ): EncryptionSupportConfig = EncryptionSupportConfig(
            ecConfig = EcConfig(ecKeyCurve),
            rsaConfig = RsaConfig(rcaKeySize),
            credentialResponseEncryptionPolicy = credentialResponseEncryptionPolicy,
        )
    }
}

data class RsaConfig(
    val rcaKeySize: Int,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = RSAEncrypter.SUPPORTED_ALGORITHMS.toList(),
) {
    init {
        require(supportedJWEAlgorithms.isNotEmpty()) { "At least one encryption algorithm must be provided" }
        val unsupportedJWEAlgorithms = supportedJWEAlgorithms.filterNot { it in RSAEncrypter.SUPPORTED_ALGORITHMS }
        require(unsupportedJWEAlgorithms.isEmpty()) {
            "Unsupported encryption algorithms: ${unsupportedJWEAlgorithms.joinToString(", ") { it.name }}"
        }
        require(supportedJWEAlgorithms.distinctBy { it.name }.size == supportedJWEAlgorithms.size) {
            "supportedJWEAlgorithms contains duplicate values"
        }
    }
}

data class EcConfig(
    val ecKeyCurve: Curve,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = ECDHEncrypter.SUPPORTED_ALGORITHMS.toList(),
) {
    init {
        require(supportedJWEAlgorithms.isNotEmpty()) { "At least one encryption algorithm must be provided" }
        val unsupportedJWEAlgorithms = supportedJWEAlgorithms.filterNot { it in ECDHEncrypter.SUPPORTED_ALGORITHMS }
        require(unsupportedJWEAlgorithms.isEmpty()) {
            "Unsupported encryption algorithms: ${unsupportedJWEAlgorithms.joinToString(", ") { it.name }}"
        }
        require(supportedJWEAlgorithms.distinctBy { it.name }.size == supportedJWEAlgorithms.size) {
            "supportedJWEAlgorithms contains duplicate values"
        }
    }
}

enum class AuthorizeIssuanceConfig {
    FAVOR_SCOPES,
    AUTHORIZATION_DETAILS,
}

/**
 * Wallet's policy concerning the metadata of the Credential Issuer.
 */
sealed interface IssuerMetadataPolicy {

    /**
     * Credential Issuer **must** provide signed metadata. Only values from signed metadata are used.
     */
    data class RequireSigned(val issuerTrust: IssuerTrust) : IssuerMetadataPolicy

    /**
     * Credential Issuer **may** provide signed metadata. If signed metadata are provided, values conveyed in the singed
     * metadata take precedence over their corresponding unsigned counterparts.
     */
    data class PreferSigned(val issuerTrust: IssuerTrust) : IssuerMetadataPolicy

    /**
     * Signed metadata are ignored. Only values conveyed using plain json elements are used.
     */
    data object IgnoreSigned : IssuerMetadataPolicy
}
