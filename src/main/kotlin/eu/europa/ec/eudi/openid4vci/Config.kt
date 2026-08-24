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
import eu.europa.ec.eudi.openid4vci.internal.ensureNotNull
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

    suspend operator fun invoke(authorizationServer: HttpsUrl, preferredClientStatusPeriod: PositiveDuration?): Provisioned

    data class Provisioned(
        val clientAttestation: ClientAttestationJWT,
        val popSigner: Signer<JWK>,
    )
}

/**
 * Provisions a [Signer] for signing DPoP Proofs.
 */
interface ProvisionDPoPSigner {
    val popAlgorithm: JwsAlgorithm

    suspend operator fun invoke(authorizationServer: HttpsUrl): Signer<JWK>
}

/**
 * Configuration options for DPoP.
 */
data class DPoPConfig(val provisionDPoPSigner: ProvisionDPoPSigner)

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
    data class None(override val id: ClientId) : ClientAuthentication

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
 * Defines a policy for validating the registration certificate policy.
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
        data class Granted(val warnings: List<PolicyViolation> = emptyList()) : Authorization
        data class NotGranted(val error: PolicyViolation) : Authorization
    }

    @JvmInline
    value class PolicyViolation(val violation: String) {
        init {
            require(violation.isNotEmpty()) { "Violation must not be empty" }
        }
    }
}

/**
 * Configuration object to pass configuration properties to the issuance components.
 *
 * @param clientAuthentication the OAuth 2.0 Client Authentication Method of the Wallet
 * @param authFlowRedirectionURI  Redirect url to be passed as the 'redirect_url' parameter to the authorization request.
 * @param encryptionSupportConfig   Configuration related to generation of encryption keys and encryption algorithms per algorithm family.
 * @param authorizeIssuanceConfig Instruction on how to assemble the authorization request. If scopes are supported
 * by the credential issuer and [AuthorizeIssuanceConfig.FAVOR_SCOPES] is selected then scopes will be used.
 * Otherwise, authorization details (RAR)
 * @param dPoPUsage an indication about whether DPoP is never to be used, supported, or required
 * @param parUsage whether to use PAR in case of authorization code grant
 * @param clock Wallet's clock
 * @param issuerMetadataPolicy policy concerning signed metadata usage
 * @param supportedCredentialReusePolicies the reuse policies supported by the wallet, used to validate against credential issuer metadata.
 * @param proofs proofs supported by the Wallet
 * @param registrationCertificatePolicy a policy for validating Registration Certificates
 * @param authResponseIssChecking Wallet's policy concerning the validation of the `iss` parameter
 * present in the authorization response, as described by the Authorization Server metadata field
 * `authorization_response_iss_parameter_supported`
 * @param grants grant types supported by the wallet
 *
 */
data class OpenId4VCIConfig(
    val clientAuthentication: ClientAuthentication,
    val authFlowRedirectionURI: URI,
    val encryptionSupportConfig: EncryptionSupportConfig,
    val authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
    val dPoPUsage: DPoPUsageOption = DPoPUsage.Never,
    val parUsage: ParUsage = ParUsage.IfSupported(),
    val clock: Clock = Clock.systemDefaultZone(),
    val issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
    val supportedCredentialReusePolicies: CredentialReusePolicies? = null,
    val proofs: ProofsConfig = ProofsConfig.Default,
    val registrationCertificatePolicy: RegistrationCertificatePolicy? = null,
    val authResponseIssChecking: AuthorizationResponseIssChecking = AuthorizationResponseIssChecking.Never,
    val grants: SupportedGrants = SupportedGrants.Both,
) {

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

        if (SupportedGrants.AuthorizationCode == grants || SupportedGrants.Both == grants) {
            ensureNotNull(authFlowRedirectionURI) {
                IllegalArgumentException(
                    "Wrong configuration: " +
                        "authFlowRedirectionURI must be provided when grants is AuthorizationCode or Both",
                )
            }
        }
    }

    /**
     * Creates a new [OpenId4VCIConfig] instance for a Wallet that uses [a Public OAuth 2.0 Client][ClientAuthentication.None].
     */
    constructor(
        clientId: ClientId,
        authFlowRedirectionURI: URI,
        encryptionSupportConfig: EncryptionSupportConfig,
        authorizeIssuanceConfig: AuthorizeIssuanceConfig = AuthorizeIssuanceConfig.FAVOR_SCOPES,
        dPoPUsage: DPoPUsageOption = DPoPUsage.Never,
        parUsage: ParUsage = ParUsage.IfSupported(),
        clock: Clock = Clock.systemDefaultZone(),
        issuerMetadataPolicy: IssuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
        supportedCredentialReusePolicies: CredentialReusePolicies? = null,
        proofs: ProofsConfig = ProofsConfig.Default,
        registrationCertificatePolicy: RegistrationCertificatePolicy? = null,
        authResponseIssChecking: AuthorizationResponseIssChecking = AuthorizationResponseIssChecking.Never,
        grants: SupportedGrants = SupportedGrants.Both,
    ) : this(
        clientAuthentication = ClientAuthentication.None(clientId),
        authFlowRedirectionURI = authFlowRedirectionURI,
        encryptionSupportConfig = encryptionSupportConfig,
        authorizeIssuanceConfig = authorizeIssuanceConfig,
        dPoPUsage = dPoPUsage,
        parUsage = parUsage,
        clock = clock,
        issuerMetadataPolicy = issuerMetadataPolicy,
        supportedCredentialReusePolicies = supportedCredentialReusePolicies,
        proofs = proofs,
        registrationCertificatePolicy = registrationCertificatePolicy,
        authResponseIssChecking = authResponseIssChecking,
        grants = grants
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
    data class Supported(override val policyTypes: Set<EudiReusePolicyType>) : CredentialReusePolicies {
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
    data class Required(override val policyTypes: Set<EudiReusePolicyType>) : CredentialReusePolicies {
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
    data class IfSupported<C : Any>(val value: C) : DPoPUsage<C>

    /**
     * DPoP usage is required. If the Authorization Server doesn't support DPoP, issuance does not proceed.
     *
     */
    data class Required<C : Any>(val value: C) : DPoPUsage<C>
}

/**
 * Wallet's policy in regard to using PAR, during a authorization code grant.
 * - [Never]: Disables PAR. Wallet will use the usual authorization code flow
 * - [IfSupported]: If authorization server advertises PAR endpoint it will be used. Otherwise, falls back
 *   to usual authorization code flow
 * - [Required]: Wallet always will place PAR request, regardless what if authorization server advertises the PAR
 *   endpoint. If PAR endpoint is not being advertised, the issuance will fail.
 */
sealed interface ParUsage : java.io.Serializable {
    data object Never : ParUsage {
        private fun readResolve(): Any = Never
    }

    data class IfSupported(val authorizationCodeDPoPBinding: Boolean = true) : ParUsage

    data class Required(val authorizationCodeDPoPBinding: Boolean = true) : ParUsage
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

    val supportedEncryptionAlgorithms: List<JWEAlgorithm> get() = buildList {
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
        ): EncryptionSupportConfig = EncryptionSupportConfig(
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
 * @property jwtProof whether the Wallet supports JWT Proofs
 * @property attestationProof whether the Wallet supports Attestation Proofs
 */
data class ProofsConfig(
    val isNoProofSupported: Boolean,
    val jwtProof: SupportedJwtProof?,
    val attestationProof: SupportedAttestationProof?,
) {

    /**
     * Indicates support for JWT Proofs.
     *
     * @property supportedAlgorithms the signing algorithms supported by the Wallet
     */
    data class SupportedJwtProof(val supportedAlgorithms: Set<JWSAlgorithm>)

    /**
     * Indicates support for Attestation Proofs.
     *
     * @property supportedAlgorithms the signing algorithms supported by the Wallet
     */
    data class SupportedAttestationProof(val supportedAlgorithms: Set<JWSAlgorithm>)

    companion object {
        /**
         * A [ProofsConfig] instance for Wallets that support issuance of attestations that require no proofs, and attestations that
         * require either JWT Proofs or Attestation Proofs signed with either ES256, ES384, or ES512.
         */
        val Default: ProofsConfig
            get() {
                val supportedAlgorithms = setOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
                return ProofsConfig(
                    true,
                    SupportedJwtProof(supportedAlgorithms),
                    SupportedAttestationProof(supportedAlgorithms),
                )
            }

        /**
         * Creates a [ProofsConfig] instance for a Wallet that supports issueance of attestations that require
         * either JWT Proofs or Attestation Proofs signed with one of the provided JWS Algorithms.
         */
        operator fun invoke(first: JWSAlgorithm, vararg remaining: JWSAlgorithm): ProofsConfig {
            val supportedAlgorithms = setOf(first, *remaining)
            return ProofsConfig(
                isNoProofSupported = false,
                jwtProof = SupportedJwtProof(supportedAlgorithms),
                attestationProof = SupportedAttestationProof(supportedAlgorithms),
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
     */
    data object AuthorizationCode : SupportedGrants

    /**
     * Wallet supports Pre-authorized Code grant.
     */
    data object PreAuthorizedCode : SupportedGrants

    /**
     * Wallet supports both Authorization Code and Pre-authorized Code grants.
     */
    data object Both : SupportedGrants
}
