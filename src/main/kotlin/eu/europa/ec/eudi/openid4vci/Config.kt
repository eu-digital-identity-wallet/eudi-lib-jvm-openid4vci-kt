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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.internal.ensure
import java.net.URI
import java.security.cert.X509Certificate
import java.time.Clock

typealias ClientId = String

/**
 * [Provisions][Provisioned] a client attestation JWT and a singer for its PoP
 */
interface ProvisionClientAttestation {
    val algorithm: JwsAlgorithm
    val popAlgorithm: JwsAlgorithm

    suspend operator fun invoke(
        authorizationServer: HttpsUrl,
        preferredClientStatusPeriod: PositiveDuration?,
    ): Provisioned

    data class Provisioned(
        val clientAttestation: ClientAttestationJWT,
        val popSigner: Signer<JWK>,
    )
}

/**
 * The base64url RFC 7638 SHA-256 thumbprint of a JWK.
 *
 * Used for the `dpop_jkt` PAR binding method (RFC 9449 §10.1).
 */
typealias JWKThumbprint = String

/**
 * Provisions a [Signer] for signing DPoP Proofs.
 */
interface ProvisionDPoPSigner {
    val popAlgorithm: JwsAlgorithm

    /**
     * Provisions the [Signer] used for signing DPoP Proofs, and, when it can be known without calling
     * [Signer.acquire], the RFC 7638 thumbprint of the signer's public key.
     *
     * The thumbprint is used for the `dpop_jkt` PAR binding method (RFC 9449 §10.1). It is `null` when the
     * signer's public key cannot be exposed without acquiring the signer.
     */
    suspend operator fun invoke(authorizationServer: HttpsUrl): Pair<Signer<JWK>, JWKThumbprint?>
}

/**
 * Configuration options for DPoP.
 */
data class DPoPConfig(
    val provisionDPoPSigner: ProvisionDPoPSigner,
)

/**
 * An indication about the Client's preference for DPoP.
 */
typealias DPoPUsageOption = DPoPUsage<DPoPConfig>

/**
 * The Client Authentication Method used by the Wallet.
 */
sealed interface ClientAuthentication : java.io.Serializable {
    /**
     * The client_id of the Wallet, issued when interacting with a credential issuer
     */
    val id: ClientId

    /**
     * None, i.e. a Public Client.
     */
    data class None(
        override val id: ClientId,
    ) : ClientAuthentication

    /**
     * Attestation-Based Client Authentication.
     */
    data class AttestationBased(
        override val id: ClientId,
        val provisionClientAttestation: ProvisionClientAttestation,
    ) : ClientAuthentication {
        init {
            require(provisionClientAttestation.algorithm.toNimbus() in TS3.ALLOWED_SIGNATURE_ALGORITHMS) {
                "Client Attestation JWT algorithm must be one of ${TS3.ALLOWED_SIGNATURE_ALGORITHMS.joinToString { it.name }}"
            }
            require(provisionClientAttestation.popAlgorithm.toNimbus() in TS3.ALLOWED_SIGNATURE_ALGORITHMS) {
                "Client Attestation POP JWT algorithm must be one of ${TS3.ALLOWED_SIGNATURE_ALGORITHMS.joinToString { it.name }}"
            }
        }
    }
}

/**
 * Defines a policy for validating the registration certificate.
 *
 * This functional interface evaluates the provided access and registration certificates
 * against a set of credential configurations to determine authorization for issuance.
 */
fun interface RegistrationCertificatePolicy {
    suspend operator fun invoke(
        accessCertificate: X509Certificate,
        registrationCertificate: String,
        issuanceContext: List<CredentialConfiguration>,
    ): Authorization

    /**
     * Represents the result of registration certificate policy evaluation.
     */
    sealed interface Authorization {
        data class Granted(
            val warnings: List<PolicyViolation> = emptyList(),
        ) : Authorization

        data class NotGranted(
            val error: PolicyViolation,
        ) : Authorization
    }

    @JvmInline
    value class PolicyViolation(
        val violation: String,
    ) {
        init {
            require(violation.isNotEmpty()) { "Violation must not be empty" }
        }
    }
}

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param clientAuthentication the OAuth 2.0 Client Authentication Method of the Wallet
 * @param encryptionSupportConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param authorizeIssuanceConfig Instruction on how to assemble the authorization request. If scopes are supported
 * by the credential issuer and [AuthorizeIssuanceConfig.FAVOR_SCOPES] is selected then scopes will be used.
 * Otherwise, authorization details (RAR)
 * @param dPoPUsage an indication about whether DPoP is never to be used, supported, or required
 * @param clock Wallet's clock
 * @param issuerMetadataPolicy policy concerning signed metadata usage
 * @param supportedCredentialReusePolicies the reuse policies supported by the wallet, used to validate against credential issuer metadata.
 * @param proofs proofs supported by the Wallet
 * @param registrationCertificatePolicy a policy for validating Registration Certificates
 * @param grants grant types supported by the wallet, along with the grant-specific options.
 * For the Authorization Code grant, see [SupportedGrants.AuthorizationCode], which carries the redirect URI, the PAR usage
 * policy, the Authorization Response `iss` checking policy and the Authorization Code DPoP binding method.
 *
 */
data class OpenId4VCIConfig(
    val clientAuthentication: ClientAuthentication,
    val encryptionSupportConfig: EncryptionSupportConfig,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
    val dPoPUsage: DPoPUsageOption = DPoPUsage.Never,
    val clock: Clock = Clock.systemDefaultZone(),
    val issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    val supportedCredentialReusePolicies: CredentialReusePolicies? = null,
    val proofs: ProofsConfig = ProofsConfig.Default,
    val registrationCertificatePolicy: RegistrationCertificatePolicy? = null,
    val grants: SupportedGrants,
) {
    /**
     * The [SupportedGrants.AuthorizationCode] configuration, when the wallet supports the Authorization Code grant
     * (either on its own, or as part of [SupportedGrants.Both]); `null` otherwise.
     */
    val authorizationCodeGrant: SupportedGrants.AuthorizationCode?
        get() =
            when (grants) {
                is SupportedGrants.AuthorizationCode -> grants
                is SupportedGrants.Both -> grants.authorizationCode
                else -> null
            }

    init {
        if (registrationCertificatePolicy != null) {
            ensure(issuerMetadataPolicy is IssuerMetadataPolicy.RequireSigned) {
                IllegalArgumentException(
                    "Wrong configuration: " +
                        "IssuerMetadataPolicy does not match RegistrationCertificatePolicy. " +
                        "When RegistrationCertificatePolicy is provided, IssuerMetadataPolicy must be RequireSigned",
                )
            }
        }
    }

    /**
     * Creates a new [OpenId4VCIConfig] instance for a Wallet that uses [a Public OAuth 2.0 Client][ClientAuthentication.None].
     */
    constructor(
        clientId: ClientId,
        encryptionSupportConfig: EncryptionSupportConfig,
        authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        dPoPUsage: DPoPUsageOption = DPoPUsage.Never,
        clock: Clock = Clock.systemDefaultZone(),
        issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
        supportedCredentialReusePolicies: CredentialReusePolicies? = null,
        proofs: ProofsConfig = ProofsConfig.Default,
        registrationCertificatePolicy: RegistrationCertificatePolicy? = null,
        grants: SupportedGrants,
    ) : this(
        clientAuthentication = ClientAuthentication.None(clientId),
        encryptionSupportConfig = encryptionSupportConfig,
        authorizeIssuanceConfig = authorizeIssuanceConfig,
        dPoPUsage = dPoPUsage,
        clock = clock,
        issuerMetadataPolicy = issuerMetadataPolicy,
        supportedCredentialReusePolicies = supportedCredentialReusePolicies,
        proofs = proofs,
        registrationCertificatePolicy = registrationCertificatePolicy,
        grants = grants,
    )
}

/**
 * Wallet's policy regarding supported credential reuse policies.
 */
sealed interface CredentialReusePolicies {
    val policyTypes: Set<EudiReusePolicyType>

    /**
     * The Wallet supports the provided reuse policies.
     */
    data class Supported(
        override val policyTypes: Set<EudiReusePolicyType>,
    ) : CredentialReusePolicies {
        init {
            require(policyTypes.isNotEmpty()) { "policyTypes must not be empty" }
            require(policyTypes.contains(EudiReusePolicyType.OnceOnly) || policyTypes.contains(EudiReusePolicyType.LimitedTime)) {
                "policyTypes must contain at least one of OnceOnly or LimitedTime"
            }
        }
    }

    /**
     * The Wallet requires at least one of the provided reuse policies to be used.
     */
    data class Required(
        override val policyTypes: Set<EudiReusePolicyType>,
    ) : CredentialReusePolicies {
        init {
            require(policyTypes.isNotEmpty()) { "policyTypes must not be empty" }
            require(policyTypes.contains(EudiReusePolicyType.OnceOnly) || policyTypes.contains(EudiReusePolicyType.LimitedTime)) {
                "policyTypes must contain at least one of OnceOnly or LimitedTime"
            }
        }
    }
}

/**
 * Wallet's policy regarding DPoP usage.
 */
sealed interface DPoPUsage<out C : Any> {
    /**
     * DPoP is never used.
     */
    data object Never : DPoPUsage<Nothing>

    /**
     * DPoP is used if supported by the Authorization Server.
     *
     */
    data class IfSupported<C : Any>(
        val value: C,
    ) : DPoPUsage<C>

    /**
     * DPoP usage is required. If the Authorization Server doesn't support DPoP, issuance does not proceed.
     *
     */
    data class Required<C : Any>(
        val value: C,
    ) : DPoPUsage<C>
}

/**
 * Wallet's policy in regard to using PAR, during a authorization code grant.
 * - [Never]: Disables PAR. Wallet will use the usual authorization code flow
 * - [IfSupported]: If authorization server advertises PAR endpoint it will be used. Otherwise, falls back
 *   to usual authorization code flow
 * - [Required]: Wallet always will place PAR request, regardless what if authorization server advertises the PAR
 *   endpoint. If PAR endpoint is not being advertised, the issuance will fail.
 *
 * How the Authorization Code is bound to the DPoP key (if at all) is configured separately via
 * [SupportedGrants.AuthorizationCode.authorizationCodeDPoPBindingMethod], per RFC 9449 §10.1.
 */
sealed interface ParUsage : java.io.Serializable {
    /**
     * Disables PAR. Wallet will use the usual authorization code flow.
     */
    data object Never : ParUsage {
        private fun readResolve(): Any = Never
    }

    /**
     * If authorization server advertises PAR endpoint it will be used. Otherwise, falls back
     * to usual authorization code flow.
     */
    data object IfSupported : ParUsage {
        private fun readResolve(): Any = IfSupported
    }

    /**
     * Wallet always will place PAR request, regardless what if authorization server advertises the PAR
     * endpoint. If PAR endpoint is not being advertised, the issuance will fail.
     */
    data object Required : ParUsage {
        private fun readResolve(): Any = Required
    }
}

/**
 * How the Authorization Code is bound to the DPoP key, per RFC 9449 §10.1.
 */
enum class AuthorizationCodeDPoPBindingMethod {
    /**
     * The Authorization Code is not bound to the DPoP key.
     */
    None,

    /**
     * Bind the Authorization Code to the DPoP key by attaching a DPoP proof in the `DPoP` header of the
     * PAR request. This method requires the use of PAR; without PAR the DPoP header cannot be used, so the
     * binding is performed via [DPoPJkt] instead.
     */
    DPoPHeader,

    /**
     * Bind the Authorization Code to the DPoP key by including the `dpop_jkt` parameter (the RFC 7638 JWK
     * thumbprint of the DPoP public key) in the PAR request body when PAR is used, or in the authorization
     * request when PAR is not used.
     */
    DPoPJkt,
}

/**
 * Wallet's policy in regard to validating the `iss` parameter present in the authorization response,
 * as described by the Authorization Server metadata field `authorization_response_iss_parameter_supported`.
 *
 * The `iss` parameter is used to mitigate mix-up attacks, by allowing the Wallet to verify that the
 * authorization response was issued by the expected Authorization Server.
 *
 * - [Never]: The Wallet never validates the `iss` parameter of the authorization response.
 * - [IfSupported]: The Wallet validates the `iss` parameter only when the Authorization Server
 *   advertises support for it (i.e. `authorization_response_iss_parameter_supported` is `true`).
 * - [Required]: The Wallet requires the Authorization Server to support the `iss` parameter. If the
 *   Authorization Server does not advertise support for it, issuance fails. Otherwise, the `iss`
 *   parameter is validated.
 */
sealed interface AuthorizationResponseIssChecking : java.io.Serializable {
    /**
     * The Wallet never validates the `iss` parameter of the authorization response.
     */
    data object Never : AuthorizationResponseIssChecking {
        private fun readResolve(): Any = Never
    }

    /**
     * The Wallet validates the `iss` parameter only when the Authorization Server
     * advertises support for it.
     */
    data object IfSupported : AuthorizationResponseIssChecking {
        private fun readResolve(): Any = IfSupported
    }

    /**
     * The Wallet requires the Authorization Server to support the `iss` parameter.
     * If the Authorization Server does not advertise support, issuance fails.
     */
    data object Required : AuthorizationResponseIssChecking {
        private fun readResolve(): Any = Required
    }
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
    val supportedEncryptionMethods: List<EncryptionMethod> = SUPPORTED_ENCRYPTION_METHODS.toList(),
) {
    init {
        require(supportedEncryptionMethods.isNotEmpty()) { "At least one encryption method must be provided" }
        val unsupportedEncryptionMethods = supportedEncryptionMethods.filterNot { it in SUPPORTED_ENCRYPTION_METHODS }
        require(unsupportedEncryptionMethods.isEmpty()) {
            "Unsupported encryption methods: ${unsupportedEncryptionMethods.joinToString(", ") { it.name }}"
        }
        require(supportedEncryptionMethods.distinctBy { it.name }.size == supportedEncryptionMethods.size) {
            "supportedEncryptionMethods contains duplicate values"
        }
    }

    val supportedEncryptionAlgorithms: List<JWEAlgorithm> get() =
        buildList {
            ecConfig?.supportedJWEAlgorithms?.let { addAll(it) }
            rsaConfig?.supportedJWEAlgorithms?.let { addAll(it) }
        }

    companion object {
        val SUPPORTED_ENCRYPTION_METHODS: Set<EncryptionMethod> get() =
            ContentCryptoProvider.SUPPORTED_ENCRYPTION_METHODS -
                EncryptionMethod.A128CBC_HS256_DEPRECATED -
                EncryptionMethod.A256CBC_HS512_DEPRECATED

        operator fun invoke(
            ecKeyCurve: Curve,
            rcaKeySize: Int,
            credentialResponseEncryptionPolicy: CredentialResponseEncryptionPolicy,
        ): EncryptionSupportConfig =
            EncryptionSupportConfig(
                ecConfig = EcConfig(ecKeyCurve),
                rsaConfig = RsaConfig(rcaKeySize),
                credentialResponseEncryptionPolicy = credentialResponseEncryptionPolicy,
            )
    }
}

data class RsaConfig(
    val rcaKeySize: Int,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = SUPPORTED_ENCRYPTION_ALGORITHMS.toList(),
) {
    init {
        require(supportedJWEAlgorithms.isNotEmpty()) { "At least one encryption algorithm must be provided" }
        val unsupportedJWEAlgorithms = supportedJWEAlgorithms.filterNot { it in SUPPORTED_ENCRYPTION_ALGORITHMS }
        require(unsupportedJWEAlgorithms.isEmpty()) {
            "Unsupported encryption algorithms: ${unsupportedJWEAlgorithms.joinToString(", ") { it.name }}"
        }
        require(supportedJWEAlgorithms.distinctBy { it.name }.size == supportedJWEAlgorithms.size) {
            "supportedJWEAlgorithms contains duplicate values"
        }
    }

    companion object {
        val SUPPORTED_ENCRYPTION_ALGORITHMS: Set<JWEAlgorithm> get() =
            setOf(JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP_384, JWEAlgorithm.RSA_OAEP_512)
    }
}

data class EcConfig(
    val ecKeyCurve: Curve,
    val supportedJWEAlgorithms: List<JWEAlgorithm> = SUPPORTED_ENCRYPTION_ALGORITHMS.toList(),
) {
    init {
        require(supportedJWEAlgorithms.isNotEmpty()) { "At least one encryption algorithm must be provided" }
        val unsupportedJWEAlgorithms = supportedJWEAlgorithms.filterNot { it in SUPPORTED_ENCRYPTION_ALGORITHMS }
        require(unsupportedJWEAlgorithms.isEmpty()) {
            "Unsupported encryption algorithms: ${unsupportedJWEAlgorithms.joinToString(", ") { it.name }}"
        }
        require(supportedJWEAlgorithms.distinctBy { it.name }.size == supportedJWEAlgorithms.size) {
            "supportedJWEAlgorithms contains duplicate values"
        }
    }

    companion object {
        val SUPPORTED_ENCRYPTION_ALGORITHMS: Set<JWEAlgorithm> get() = ECDHEncrypter.SUPPORTED_ALGORITHMS
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
     *
     * @param issuerTrust trust anchor used to validate the certificate chain of the signed metadata.
     * @param allowedJwsAlgorithms the set of JWS algorithms accepted for the signature of the signed metadata.
     * Defaults to the algorithms allowed by the TS3 profile ([TS3.ALLOWED_SIGNATURE_ALGORITHMS]), i.e. ES256, ES384 and ES512.
     */
    data class RequireSigned(
        val issuerTrust: CertificateChainTrust,
        val allowedJwsAlgorithms: Set<JWSAlgorithm> = TS3.ALLOWED_SIGNATURE_ALGORITHMS,
    ) : IssuerMetadataPolicy {
        init {
            require(allowedJwsAlgorithms.isNotEmpty()) { "allowedJwsAlgorithms must not be empty" }
        }

        @Deprecated(message = "Use constructor passing CertificateChainTrust", ReplaceWith("RequireSigned"))
        constructor(issuerTrust: IssuerTrust) : this(issuerTrust.certificateChainTrust)
    }

    /**
     * Credential Issuer **may** provide signed metadata. If signed metadata are provided, values conveyed in the singed
     * metadata take precedence over their corresponding unsigned counterparts.
     *
     * @param issuerTrust trust anchor used to validate the certificate chain of the signed metadata.
     * @param allowedJwsAlgorithms the set of JWS algorithms accepted for the signature of the signed metadata.
     * Defaults to the algorithms allowed by the TS3 profile ([TS3.ALLOWED_SIGNATURE_ALGORITHMS]), i.e. ES256, ES384 and ES512.
     */
    data class PreferSigned(
        val issuerTrust: CertificateChainTrust,
        val allowedJwsAlgorithms: Set<JWSAlgorithm> = TS3.ALLOWED_SIGNATURE_ALGORITHMS,
    ) : IssuerMetadataPolicy {
        init {
            require(allowedJwsAlgorithms.isNotEmpty()) { "allowedJwsAlgorithms must not be empty" }
        }

        @Deprecated(message = "Use constructor passing CertificateChainTrust", ReplaceWith("PreferSigned"))
        constructor(issuerTrust: IssuerTrust) : this(issuerTrust.certificateChainTrust)
    }

    /**
     * Signed metadata are ignored. Only values conveyed using plain json elements are used.
     */
    data object IgnoreSigned : IssuerMetadataPolicy
}

/**
 * Wallet supported proofs.
 *
 * @property isNoProofSupported whether the Wallet supports issuance of attestations that require no proofs
 * @property jwtProofWithKeyAttestation whether the Wallet supports JWT Proof with Key Attestation
 * @property attestationProof whether the Wallet supports Attestation Proof
 * @property jwtProofsWithoutKeyAttestation whether the Wallet supports JWT Proofs without Key Attestation
 */
data class ProofsConfig(
    val isNoProofSupported: Boolean,
    val jwtProofWithKeyAttestation: SupportedJwtProof?,
    val attestationProof: SupportedAttestationProof?,
    val jwtProofsWithoutKeyAttestation: SupportedJwtProof?,
) {
    /**
     * Indicates support for JWT Proofs.
     *
     * @property supportedAlgorithms the signing algorithms supported by the Wallet
     */
    data class SupportedJwtProof(
        val supportedAlgorithms: Set<JWSAlgorithm>,
    ) {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least one supported algorithm must be provided." }
        }
    }

    /**
     * Indicates support for Attestation Proofs.
     *
     * @property supportedAlgorithms the signing algorithms supported by the Wallet
     */
    data class SupportedAttestationProof(
        val supportedAlgorithms: Set<JWSAlgorithm>,
    ) {
        init {
            require(supportedAlgorithms.isNotEmpty()) { "At least one supported algorithm must be provided." }
        }
    }

    companion object {
        /**
         * A [ProofsConfig] instance for Wallets that support issuance of attestations that require no proofs, and attestations that
         * require either JWT Proofs with Key Attestations or Attestation Proofs signed with either ES256, ES384, or ES512.
         */
        val Default: ProofsConfig
            get() {
                val supportedAlgorithms = setOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
                return ProofsConfig(
                    isNoProofSupported = true,
                    jwtProofWithKeyAttestation = SupportedJwtProof(supportedAlgorithms),
                    attestationProof = SupportedAttestationProof(supportedAlgorithms),
                    jwtProofsWithoutKeyAttestation = null,
                )
            }

        /**
         * Creates a [ProofsConfig] instance for a Wallet that supports issuance of attestations that require
         * either JWT Proofs with Key Attestation, or Attestation Proofs signed with one of the provided JWS Algorithms.
         */
        operator fun invoke(
            first: JWSAlgorithm,
            vararg remaining: JWSAlgorithm,
        ): ProofsConfig {
            val supportedAlgorithms = setOf(first, *remaining)
            return ProofsConfig(
                isNoProofSupported = false,
                jwtProofWithKeyAttestation = SupportedJwtProof(supportedAlgorithms),
                attestationProof = SupportedAttestationProof(supportedAlgorithms),
                jwtProofsWithoutKeyAttestation = null,
            )
        }
    }
}

/**
 * Wallet-supported grant types.
 */
sealed interface SupportedGrants {
    /**
     * Wallet supports Authorization Code grant.
     *
     * @param authFlowRedirectionURI the redirect URI to be passed as the `redirect_uri` parameter of the authorization request.
     * @param parUsage the wallet's policy regarding the use of the PAR endpoint.
     * @param authResponseIssChecking the wallet's policy concerning the validation of the `iss` parameter of the authorization response.
     * @param authorizationCodeDPoPBindingMethod how the Authorization Code is bound to the DPoP key when PAR is used, per RFC 9449 §10.1.
     */
    data class AuthorizationCode(
        val authFlowRedirectionURI: URI,
        val parUsage: ParUsage = ParUsage.IfSupported,
        val authResponseIssChecking: AuthorizationResponseIssChecking = AuthorizationResponseIssChecking.IfSupported,
        val authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPHeader,
    ) : SupportedGrants

    /**
     * Wallet supports Pre-authorized Code grant.
     */
    data object PreAuthorizedCode : SupportedGrants

    /**
     * Wallet supports both Authorization Code and Pre-authorized Code grants.
     *
     * @param authorizationCode the configuration of the Authorization Code grant.
     */
    data class Both(
        val authorizationCode: AuthorizationCode,
    ) : SupportedGrants
}
