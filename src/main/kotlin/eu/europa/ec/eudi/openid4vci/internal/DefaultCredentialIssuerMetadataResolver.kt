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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.OctetSequenceKey
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.security.cert.X509Certificate
import java.util.*

internal class DefaultCredentialIssuerMetadataResolver(
    private val httpClient: HttpClient,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(
        issuer: CredentialIssuerId,
        policy: IssuerMetadataPolicy,
    ): Result<CredentialIssuerMetadata> = runCatching {
        val wellKnownUrl = issuer.wellKnown()
        val json = try {
            httpClient.get(wellKnownUrl).body<String>()
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
        }

        val unsignedMetadata = try {
            JsonSupport.decodeFromString<CredentialIssuerMetadataTO>(json)
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(t)
        }

        suspend fun signedMetadata(issuerTrust: IssuerTrust): CredentialIssuerMetadataTO? =
            unsignedMetadata.signedMetadata?.let { signedMetadataJwt ->
                parseAndVerifySignedMetadata(
                    signedMetadataJwt,
                    issuerTrust,
                    issuer,
                ).getOrElse { throw CredentialIssuerMetadataError.InvalidSignedMetadata(it) }
            }

        when (policy) {
            is IssuerMetadataPolicy.RequireSigned -> {
                val signedMetadata = signedMetadata(policy.issuerTrust) ?: throw CredentialIssuerMetadataError.MissingSignedMetadata()
                signedMetadata.toDomain()
            }

            is IssuerMetadataPolicy.PreferSigned -> {
                val signedMetadata = signedMetadata(policy.issuerTrust)
                signedMetadata?.toDomain(unsignedMetadata) ?: unsignedMetadata.toDomain()
            }

            IssuerMetadataPolicy.RequireUnsigned -> unsignedMetadata.toDomain()
        }.also { metaData ->
            ensure(metaData.credentialIssuerIdentifier == issuer) {
                InvalidCredentialIssuerId(
                    IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                )
            }
        }
    }
}

private fun CredentialIssuerId.wellKnown() = URLBuilder(Url(value.value.toURI()))
    .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
    .build()
    .toURI()
    .toURL()

/**
 * Parses and verifies the signature of a Signed JWT that contains Credential Issuer Metadata.
 *
 * @param jwt the Signed JWT to parse and verify
 * @param issuerTrust trust anchor for the issuer of the signed metadata
 * @param issuer the id of the Credential Issuer whose signed metadata to parse
 */
private suspend fun parseAndVerifySignedMetadata(
    jwt: String,
    issuerTrust: IssuerTrust,
    issuer: CredentialIssuerId,
): Result<CredentialIssuerMetadataTO> = runCatching {
    val signedJwt = SignedJWT.parse(jwt)

    require(issuerTrust.verify(signedJwt)) { "signature verification of signed metadata failed" }

    val claimSet = signedJwt.jwtClaimsSet
    val claimSetVerifier = signedMetadataClaimSetVerifier(issuer)
    claimSetVerifier.verify(claimSet, null)

    val json = JSONObjectUtils.toJSONString(claimSet.toJSONObject())
    JsonSupport.decodeFromString<CredentialIssuerMetadataTO>(json)
}

/**
 * Verifies [jwt] is signed by a trusted issuer.
 */
private suspend fun IssuerTrust.verify(jwt: SignedJWT): Boolean {
    fun JWK.jwsVerifier(): JWSVerifier =
        when (this) {
            is RSAKey -> RSASSAVerifier(this)
            is ECKey -> ECDSAVerifier(this)
            is OctetKeyPair -> Ed25519Verifier(this)
            is OctetSequenceKey -> MACVerifier(this)
            else -> throw IllegalArgumentException("Unsupported JWK type '${this.javaClass}'")
        }

    fun X509Certificate.jwsVerifier(): JWSVerifier = JWK.parse(this).jwsVerifier()

    val jwsVerifier = when (this) {
        is IssuerTrust.ByPublicKey -> {
            val headerJwk = requireNotNull(jwt.header.jwk) { "missing 'jwk' header claim" }
            require(jwk == headerJwk) { "jwk in 'jwk' header claim is not trusted" }
            jwk.jwsVerifier()
        }

        is IssuerTrust.ByCertificateChain -> {
            val certChain = requireNotNull(jwt.header.x509CertChain) {
                "missing 'x5c' header claim"
            }.let { X509CertChainUtils.parse(it) }
            require(certificateChainTrust.isTrusted(certChain)) {
                "certificate chain in 'x5c' header claim is not trusted"
            }
            certChain.first().jwsVerifier()
        }
    }

    return jwt.verify(jwsVerifier)
}

/**
 * Gets a [JWTClaimsSetVerifier] for the claims of a Signed JWT that contains the signed metadata of a Credential Issuer.
 *
 * The verifier:
 * 1. Accepts all audiences
 * 2. Requires 'sub' claim to be [subject]
 * 3. Requires 'iat', 'iss', 'sub' claims to be present
 * 4. Ensures 'signed_metadata' claim is not present
 * 5. Ensures the claim set can be used according to 'exp' and 'nbf' if present
 */
private fun signedMetadataClaimSetVerifier(subject: CredentialIssuerId): JWTClaimsSetVerifier<SecurityContext> =
    DefaultJWTClaimsVerifier(
        null,
        JWTClaimsSet.Builder()
            .subject(subject.value.value.toExternalForm())
            .build(),
        setOf("iat", "iss", "sub"),
        setOf("signed_metadata"),
    )

/**
 * The metadata of a Credentials that can be issued by a Credential Issuer.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("format")
private sealed interface CredentialSupportedTO {

    val format: String
    val scope: String?
    val cryptographicBindingMethodsSupported: List<String>?
    val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>?
    val display: List<CredentialSupportedDisplayTO>?

    fun toDomain(): CredentialConfiguration
}

@Serializable
private data class ProofTypeSupportedMetaTO(
    @SerialName("proof_signing_alg_values_supported") val algorithms: List<String> = emptyList(),
    @SerialName("key_attestations_required") val keyAttestationRequirement: KeyAttestationRequirementTO? = null,
)

@Serializable
private data class KeyAttestationRequirementTO(
    @SerialName("key_storage") val keyStorage: List<String>? = null,
    @SerialName("user_authentication") val userAuthentication: List<String>? = null,
)

@Serializable
private data class PolicyTO(
    @SerialName("one_time_use") val oneTimeUse: Boolean,
    @SerialName("batch_size") val batchSize: Int? = null,
)

/**
 * The data of a Verifiable Credentials issued as an ISO mDL.
 */
@Suppress("unused")
@Serializable
@SerialName(FORMAT_MSO_MDOC)
private data class MsdMdocCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_MSO_MDOC,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<JsonPrimitive>? = null,
    @SerialName("credential_alg_values_supported") val isoCredentialSigningAlgorithmsSupported: List<JsonPrimitive>? = null,
    @SerialName("credential_crv_values_supported") val isoCredentialCurvesSupported: List<Int>? = null,
    @SerialName("policy") val isoPolicy: PolicyTO? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("doctype") @Required val docType: String,
    @SerialName("claims") val claims: List<ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_MSO_MDOC) { "invalid format '$format'" }
    }

    override fun toDomain(): MsoMdocCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }

        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported
            .orEmpty().mapNotNull { it.toCoseAlgorithm()?.name() }
        val coseAlgs = isoCredentialSigningAlgorithmsSupported.orEmpty().map {
            requireNotNull(it.toCoseAlgorithm()) { "Expecting COSE algorithm, yet got $it" }
        }
        val coseCurves = isoCredentialCurvesSupported.orEmpty().map { CoseCurve(it) }
        val policy = isoPolicy?.let { policy -> MsoMdocPolicy(policy.oneTimeUse, policy.batchSize) }

        return MsoMdocCredential(
            scope,
            bindingMethods,
            cryptographicSuitesSupported,
            coseAlgs,
            coseCurves,
            policy,
            proofTypesSupported,
            display,
            docType,
            claims?.map { it.toDomain() }.orEmpty(),
        )
    }
}

@Suppress("unused")
@Serializable
@SerialName(FORMAT_SD_JWT_VC)
private data class SdJwtVcCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_SD_JWT_VC,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("vct") val type: String,
    @SerialName("claims") val claims: List<ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_SD_JWT_VC) { "invalid format '$format'" }
    }

    override fun toDomain(): SdJwtVcCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }

        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported.orEmpty()

        return SdJwtVcCredential(
            scope,
            bindingMethods,
            cryptographicSuitesSupported,
            proofTypesSupported,
            display,
            type,
            claims?.map { it.toDomain() }.orEmpty(),
        )
    }
}

@Serializable
private data class W3CJsonLdCredentialDefinitionTO(
    @SerialName("@context") val context: List<String>,
    @SerialName("type") val types: List<String>,
) {

    fun toDomain(): W3CJsonLdCredentialDefinition = W3CJsonLdCredentialDefinition(
        context = context.map { URI(it).toURL() },
        type = types,
    )
}

/**
 * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
 */
@Suppress("unused")
@Serializable
@SerialName(FORMAT_W3C_JSONLD_DATA_INTEGRITY)
private data class W3CJsonLdDataIntegrityCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_W3C_JSONLD_DATA_INTEGRITY,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: W3CJsonLdCredentialDefinitionTO,
    @SerialName("claims") val claims: List<ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_W3C_JSONLD_DATA_INTEGRITY) { "invalid format '$format'" }
    }

    override fun toDomain(): W3CJsonLdDataIntegrityCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }
        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported.orEmpty()

        return W3CJsonLdDataIntegrityCredential(
            scope = scope,
            cryptographicBindingMethodsSupported = bindingMethods,
            credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
            proofTypesSupported = proofTypesSupported,
            display = display,
            credentialDefinition = credentialDefinition.toDomain(),
            claims = claims?.map { it.toDomain() }.orEmpty(),
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
 */
@Suppress("unused")
@Serializable
@SerialName(FORMAT_W3C_JSONLD_SIGNED_JWT)
private data class W3CJsonLdSignedJwtCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_W3C_JSONLD_SIGNED_JWT,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: W3CJsonLdCredentialDefinitionTO,
    @SerialName("claims") val claims: List<ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_W3C_JSONLD_SIGNED_JWT) { "invalid format '$format'" }
    }

    override fun toDomain(): W3CJsonLdSignedJwtCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }

        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported.orEmpty()

        return W3CJsonLdSignedJwtCredential(
            scope = scope,
            cryptographicBindingMethodsSupported = bindingMethods,
            credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
            proofTypesSupported = proofTypesSupported,
            display = display,
            credentialDefinition = credentialDefinition.toDomain(),
            claims = claims?.map { it.toDomain() }.orEmpty(),
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
@Suppress("unused")
@Serializable
@SerialName(FORMAT_W3C_SIGNED_JWT)
private data class W3CSignedJwtCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_W3C_SIGNED_JWT,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofTypeSupportedMetaTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("claims") val claims: List<ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_W3C_SIGNED_JWT) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("type") val types: List<String>,
        @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
    ) {
        fun toDomain(): W3CSignedJwtCredential.CredentialDefinition =
            W3CSignedJwtCredential.CredentialDefinition(
                type = types,
            )
    }

    override fun toDomain(): W3CSignedJwtCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }

        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported.orEmpty()

        return W3CSignedJwtCredential(
            scope = scope,
            cryptographicBindingMethodsSupported = bindingMethods,
            credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
            proofTypesSupported = proofTypesSupported,
            display = display,
            credentialDefinition = credentialDefinition.toDomain(),
            claims = claims?.map { it.toDomain() }.orEmpty(),
        )
    }
}

@Serializable
private data class BatchCredentialIssuanceTO(
    @SerialName("batch_size") @Required val batchSize: Int,
)

/**
 * Unvalidated unsigned metadata of a Credential Issuer.
 */
@Serializable
private data class CredentialIssuerMetadataTO(
    @SerialName("credential_issuer") val credentialIssuerIdentifier: String? = null,
    @SerialName("authorization_servers") val authorizationServers: List<String>? = null,
    @SerialName("credential_endpoint")val credentialEndpoint: String? = null,
    @SerialName("nonce_endpoint") val nonceEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("notification_endpoint") val notificationEndpoint: String? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
    @SerialName("batch_credential_issuance") val batchCredentialIssuance: BatchCredentialIssuanceTO? = null,
    @SerialName("signed_metadata") val signedMetadata: String? = null,
    @SerialName("credential_configurations_supported") val credentialConfigurationsSupported: Map<String, CredentialSupportedTO>? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
)

/**
 * Converts this [CredentialResponseEncryptionTO] to a [CredentialResponseEncryption].
 */
private fun CredentialResponseEncryptionTO?.toDomain(): CredentialResponseEncryption {
    fun CredentialResponseEncryptionTO.algorithmsAndMethods(): SupportedEncryptionAlgorithmsAndMethods {
        val encryptionAlgorithms = algorithmsSupported.map { JWEAlgorithm.parse(it) }
        val encryptionMethods = methodsSupported.map { EncryptionMethod.parse(it) }
        return SupportedEncryptionAlgorithmsAndMethods(encryptionAlgorithms, encryptionMethods)
    }

    return if (null == this) {
        CredentialResponseEncryption.NotSupported
    } else {
        if (encryptionRequired) {
            CredentialResponseEncryption.Required(algorithmsAndMethods())
        } else {
            CredentialResponseEncryption.SupportedNotRequired(algorithmsAndMethods())
        }
    }
}

@Serializable
private data class CredentialResponseEncryptionTO(
    @SerialName("alg_values_supported") val algorithmsSupported: List<String>,
    @SerialName("enc_values_supported") val methodsSupported: List<String>,
    @SerialName("encryption_required") val encryptionRequired: Boolean = false,
)

/**
 * Display properties of a supported credential type for a certain language.
 */
@Serializable
private data class CredentialSupportedDisplayTO(
    @SerialName("name") @Required val name: String,
    @SerialName("locale") val locale: String? = null,
    @SerialName("logo") val logo: LogoObject? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("background_image") val backgroundImage: BackgroundImageTO? = null,
    @SerialName("text_color") val textColor: String? = null,
) {
    /**
     * Utility method to convert a [CredentialSupportedDisplayTO] transfer object to the respective [Display] domain object.
     */
    fun toDomain(): Display {
        fun LogoObject.toLogo(): Display.Logo =
            Display.Logo(
                uri?.let { URI.create(it) },
                alternativeText,
            )

        fun BackgroundImageTO.toURI(): URI =
            URI.create(uri)

        return Display(
            name,
            locale?.let { Locale.forLanguageTag(it) },
            logo?.toLogo(),
            description,
            backgroundColor,
            backgroundImage?.toURI(),
            textColor,
        )
    }
}

/**
 * Logo information.
 */
@Serializable
private data class BackgroundImageTO(
    @SerialName("uri") val uri: String,
)

/**
 * Logo information.
 */
@Serializable
private data class LogoObject(
    @SerialName("uri") val uri: String? = null,
    @SerialName("alt_text") val alternativeText: String? = null,
)

/**
 * The details of a Claim.
 */
@Serializable
private data class ClaimTO(
    @SerialName("path") val path: JsonArray,
    @SerialName("mandatory") val mandatory: Boolean? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
) {
    fun toDomain(): Claim =
        Claim(
            mandatory = mandatory == true,
            path = path.asClaimPath(),
            display = display?.map { it.toClaimDisplay() } ?: emptyList(),
        )
}

/**
 * Display properties of a Claim.
 */
@Serializable
private data class DisplayTO(
    @SerialName("name") val name: String? = null,
    @SerialName("locale") val locale: String? = null,
    @SerialName("logo") val logo: LogoObject? = null,
) {
    /**
     * Converts a [DisplayTO] to a [Display] instance.
     */
    fun toDomain(): Display {
        fun LogoObject.toLogo(): Display.Logo =
            Display.Logo(uri?.let { URI.create(it) }, alternativeText)
        return Display(name ?: "", locale?.let { Locale.forLanguageTag(it) }, logo?.toLogo())
    }

    fun toClaimDisplay(): Claim.Display =
        Claim.Display(name, locale?.let { languageTag -> Locale.forLanguageTag(languageTag) })
}

private fun Map<String, ProofTypeSupportedMetaTO>?.toProofTypes(): ProofTypesSupported =
    when (this) {
        null -> ProofTypesSupported.Empty
        else -> {
            val values = map { (type, meta) -> proofTypeMeta(type, meta) }.toSet()
            ProofTypesSupported(values)
        }
    }

private fun proofTypeMeta(type: String, meta: ProofTypeSupportedMetaTO): ProofTypeMeta =
    when (type) {
        "jwt" -> ProofTypeMeta.Jwt(
            algorithms = meta.algorithms.map {
                JWSAlgorithm.parse(it)
            },
            keyAttestationRequirement = meta.keyAttestationRequirement.toDomain(),
        )

        "ldp_vp" -> ProofTypeMeta.LdpVp
        else -> ProofTypeMeta.Unsupported(type)
    }

private fun KeyAttestationRequirementTO?.toDomain(): KeyAttestationRequirement = when {
    this == null -> KeyAttestationRequirement.NotRequired
    this.keyStorage.isNullOrEmpty() && this.userAuthentication.isNullOrEmpty() -> KeyAttestationRequirement.RequiredNoConstraints
    else -> KeyAttestationRequirement.Required(this.keyStorage.orEmpty(), this.userAuthentication.orEmpty())
}

/**
 * Utility method to convert a list of string to a list of [CryptographicBindingMethod].
 */
private fun cryptographicBindingMethodOf(s: String): CryptographicBindingMethod =
    when {
        s == "jwk" -> CryptographicBindingMethod.JWK
        s == "cose_key" -> CryptographicBindingMethod.COSE
        s.startsWith("did") -> CryptographicBindingMethod.DID(s)
        else -> error("Unknown Cryptographic Binding Method '$s'")
    }

private fun JsonPrimitive.toCoseAlgorithm(): CoseAlgorithm? {
    fun Int.toCose() = CoseAlgorithm(this)
    fun String.toCoseByName() = CoseAlgorithm.byName(this)
    fun String.toCodeByValue() = toIntOrNull()?.toCose()
    val strOrNull by lazy { contentOrNull }
    return intOrNull?.toCose() ?: strOrNull?.toCodeByValue() ?: strOrNull?.toCoseByName()
}

/**
 * Converts and validates [CredentialIssuerMetadataTO] as [CredentialIssuerMetadata] instance.
 *
 * Values missing from [this] are taken from [fallback] when provided.
 */
private fun CredentialIssuerMetadataTO.toDomain(
    fallback: CredentialIssuerMetadataTO? = null,
): CredentialIssuerMetadata {
    fun ensureHttpsUrl(s: String, ex: (Throwable) -> Throwable) = HttpsUrl(s).ensureSuccess(ex)

    val credentialIssuerIdentifier = ensureNotNull(credentialIssuerIdentifier ?: fallback?.credentialIssuerIdentifier) {
        InvalidCredentialIssuerId(IllegalArgumentException("missing credential_issuer"))
    }.let {
        CredentialIssuerId(it).ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialIssuerId)
    }

    val authorizationServers = (authorizationServers ?: fallback?.authorizationServers)
        ?.map { ensureHttpsUrl(it, CredentialIssuerMetadataValidationError::InvalidAuthorizationServer) }
        ?: listOf(credentialIssuerIdentifier.value)

    val credentialEndpoint = ensureNotNull(credentialEndpoint ?: fallback?.credentialEndpoint) {
        CredentialIssuerMetadataValidationError.InvalidCredentialEndpoint(IllegalArgumentException("missing credential_endpoint"))
    }.let {
        CredentialIssuerEndpoint(it).ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialEndpoint)
    }

    val nonceEndpoint = (nonceEndpoint ?: fallback?.nonceEndpoint)
        ?.let {
            CredentialIssuerEndpoint(it).ensureSuccess(CredentialIssuerMetadataValidationError::InvalidNonceEndpoint)
        }

    val deferredCredentialEndpoint = (deferredCredentialEndpoint ?: fallback?.deferredCredentialEndpoint)
        ?.let {
            CredentialIssuerEndpoint(it).ensureSuccess(CredentialIssuerMetadataValidationError::InvalidDeferredCredentialEndpoint)
        }

    val notificationEndpoint = (notificationEndpoint ?: fallback?.notificationEndpoint)
        ?.let {
            CredentialIssuerEndpoint(it).ensureSuccess(CredentialIssuerMetadataValidationError::InvalidNotificationEndpoint)
        }

    val credentialsSupported = (credentialConfigurationsSupported ?: fallback?.credentialConfigurationsSupported)
        ?.map { (id, credentialSupportedTO) ->
            val credentialId = CredentialConfigurationIdentifier(id)
            val credential = runCatching {
                credentialSupportedTO.toDomain()
            }.ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialsSupported)
            credentialId to credential
        }?.toMap()
    ensure(!credentialsSupported.isNullOrEmpty()) { CredentialIssuerMetadataValidationError.CredentialsSupportedRequired() }

    val display = (display ?: fallback?.display)
        ?.map(DisplayTO::toDomain)
        ?: emptyList()

    val batchIssuance = (batchCredentialIssuance ?: fallback?.batchCredentialIssuance)
        ?.let {
            runCatching {
                BatchCredentialIssuance.Supported(it.batchSize)
            }.ensureSuccess { CredentialIssuerMetadataValidationError.InvalidBatchSize() }
        } ?: BatchCredentialIssuance.NotSupported

    val credentialResponseEncryption = (credentialResponseEncryption ?: fallback?.credentialResponseEncryption).toDomain()

    return CredentialIssuerMetadata(
        credentialIssuerIdentifier,
        authorizationServers,
        credentialEndpoint,
        nonceEndpoint,
        deferredCredentialEndpoint,
        notificationEndpoint,
        credentialResponseEncryption,
        batchIssuance,
        credentialsSupported,
        display,
    )
}
