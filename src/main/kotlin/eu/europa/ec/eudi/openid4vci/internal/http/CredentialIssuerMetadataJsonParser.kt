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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import eu.europa.ec.eudi.openid4vci.internal.ensure
import eu.europa.ec.eudi.openid4vci.internal.ensureSuccess
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.net.URI
import java.util.*

internal object CredentialIssuerMetadataJsonParser {
    fun parseMetaData(json: String): CredentialIssuerMetadata {
        val credentialIssuerMetadataObject = try {
            JsonSupport.decodeFromString<CredentialIssuerMetadataTO>(json)
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(t)
        }
        return credentialIssuerMetadataObject.toDomain()
    }
}

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
 * Unvalidated metadata of a Credential Issuer.
 */
@Serializable
private data class CredentialIssuerMetadataTO(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("authorization_servers") val authorizationServers: List<String>? = null,
    @SerialName("credential_endpoint") @Required val credentialEndpoint: String,
    @SerialName("nonce_endpoint") val nonceEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("notification_endpoint") val notificationEndpoint: String? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
    @SerialName("batch_credential_issuance") val batchCredentialIssuance: BatchCredentialIssuanceTO? = null,
    @SerialName("signed_metadata") val signedMetadata: String? = null,
    @SerialName("credential_configurations_supported") val credentialConfigurationsSupported: Map<String, CredentialSupportedTO> =
        emptyMap(),
    @SerialName("display") val display: List<DisplayTO>? = null,
) {
    /**
     * Converts and validates  a [CredentialIssuerMetadataTO] as a [CredentialIssuerMetadata] instance.
     */
    fun toDomain(): CredentialIssuerMetadata {
        fun ensureHttpsUrl(s: String, ex: (Throwable) -> Throwable) = HttpsUrl(s).ensureSuccess(ex)

        val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
            .ensureSuccess(::InvalidCredentialIssuerId)

        val authorizationServers = authorizationServers
            ?.map { ensureHttpsUrl(it, CredentialIssuerMetadataValidationError::InvalidAuthorizationServer) }
            ?: listOf(credentialIssuerIdentifier.value)

        val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
            .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialEndpoint)

        val nonceEndpoint = nonceEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidNonceEndpoint)
        }

        val deferredCredentialEndpoint = deferredCredentialEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidDeferredCredentialEndpoint)
        }
        val notificationEndpoint = notificationEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidNotificationEndpoint)
        }

        ensure(credentialConfigurationsSupported.isNotEmpty()) {
            CredentialIssuerMetadataValidationError.CredentialsSupportedRequired()
        }
        val credentialsSupported = credentialConfigurationsSupported.map { (id, credentialSupportedTO) ->
            val credentialId = CredentialConfigurationIdentifier(id)
            val credential = runCatching { credentialSupportedTO.toDomain() }
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialsSupported)
            credentialId to credential
        }.toMap()

        val display = display?.map(DisplayTO::toDomain) ?: emptyList()
        val batchIssuance = batchCredentialIssuance?.let {
            runCatching { BatchCredentialIssuance.Supported(it.batchSize) }.ensureSuccess {
                CredentialIssuerMetadataValidationError.InvalidBatchSize()
            }
        } ?: BatchCredentialIssuance.NotSupported

        return CredentialIssuerMetadata(
            credentialIssuerIdentifier,
            authorizationServers,
            credentialEndpoint,
            nonceEndpoint,
            deferredCredentialEndpoint,
            notificationEndpoint,
            credentialResponseEncryption(),
            batchIssuance,
            credentialsSupported,
            display,
        )
    }

    private fun credentialResponseEncryption(): CredentialResponseEncryption {
        fun algsAndMethods(): SupportedEncryptionAlgorithmsAndMethods {
            requireNotNull(credentialResponseEncryption)
            val encryptionAlgorithms = credentialResponseEncryption.algorithmsSupported.map { JWEAlgorithm.parse(it) }
            val encryptionMethods = credentialResponseEncryption.methodsSupported.map { EncryptionMethod.parse(it) }
            return SupportedEncryptionAlgorithmsAndMethods(encryptionAlgorithms, encryptionMethods)
        }
        return when {
            credentialResponseEncryption == null -> CredentialResponseEncryption.NotSupported
            credentialResponseEncryption.encryptionRequired -> CredentialResponseEncryption.Required(algsAndMethods())
            else -> CredentialResponseEncryption.SupportedNotRequired(algsAndMethods())
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
            mandatory = mandatory ?: false,
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
     * Converts a [DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
     */
    fun toDomain(): CredentialIssuerMetadata.Display {
        fun LogoObject.toLogo(): CredentialIssuerMetadata.Display.Logo =
            CredentialIssuerMetadata.Display.Logo(uri?.let { URI.create(it) }, alternativeText)
        return CredentialIssuerMetadata.Display(name, locale, logo?.toLogo())
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
