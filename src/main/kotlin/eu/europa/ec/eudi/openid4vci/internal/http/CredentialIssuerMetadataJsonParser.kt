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
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import java.net.URI
import java.net.URL
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
    val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>?
    val display: List<CredentialSupportedDisplayTO>?

    fun toDomain(): CredentialConfiguration
}

@Serializable
private data class ProofSigningAlgorithmsSupportedTO(
    @SerialName("proof_signing_alg_values_supported") val algorithms: List<JsonPrimitive> = emptyList(),
    @SerialName("proof_alg_values_supported") val cwtAlgorithms: List<Int> = emptyList(),
    @SerialName("proof_crv_values_supported") val cwtCurves: List<Int> = emptyList(),
)

@Serializable
private data class PolicyTO(
    @SerialName("one_time_use") val oneTimeUse: Boolean,
    @SerialName("batch_size") val batchSize: Int? = null,
)

/**
 * The data of a Verifiable Credentials issued as an ISO mDL.
 */
@Serializable
@SerialName(FORMAT_MSO_MDOC)
private data class MsdMdocCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_MSO_MDOC,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    val credentialSigningAlgorithmsSupported: List<JsonPrimitive>? = null,
    @SerialName("credential_alg_values_supported") val isoCredentialSigningAlgorithmsSupported: List<Int>? = null,
    @SerialName("credential_crv_values_supported") val isoCredentialCurvesSupported: List<Int>? = null,
    @SerialName("policy") val isoPolicy: PolicyTO? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("doctype") @Required val docType: String,
    @SerialName("claims") val claims: Map<String, Map<String, ClaimTO>>? = null,
    @SerialName("order") val order: List<String>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_MSO_MDOC) { "invalid format '$format'" }
    }

    override fun toDomain(): MsoMdocCredential {
        val bindingMethods = cryptographicBindingMethodsSupported.orEmpty()
            .map { cryptographicBindingMethodOf(it) }

        val display = display.orEmpty().map { it.toDomain() }
        val proofTypesSupported = proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = credentialSigningAlgorithmsSupported.orEmpty().mapNotNull { alg ->
            if (alg.isString) alg.contentOrNull
            else {
                val asInt = alg.intOrNull
                asInt?.let { CoseAlgorithm.invoke(it).getOrNull()?.name() }
            }
        }
        val coseAlgs = isoCredentialSigningAlgorithmsSupported.orEmpty().map { CoseAlgorithm(it).getOrThrow() }
        val coseCurves = isoCredentialCurvesSupported.orEmpty().map { CoseCurve(it).getOrThrow() }
        val policy = isoPolicy?.let { policy -> MsoMdocPolicy(policy.oneTimeUse, policy.batchSize) }

        fun claims(): MsoMdocClaims = claims.orEmpty().mapValues { (_, claims) ->
            claims.mapValues { (_, claim) ->
                claim.let { claimObject ->
                    Claim(
                        claimObject.mandatory ?: false,
                        claimObject.valueType,
                        claimObject.display?.map { displayObject ->
                            Claim.Display(
                                displayObject.name,
                                displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                            )
                        } ?: emptyList(),
                    )
                }
            }
        }

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
            claims(),
            order ?: emptyList(),
        )
    }
}

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
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("vct") val type: String,
    @SerialName("claims") val claims: Map<String, ClaimTO>? = null,
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
            claims?.mapValues { (_, claim) ->
                claim.let {
                    Claim(
                        it.mandatory ?: false,
                        it.valueType,
                        it.display.orEmpty().map { displayObject ->
                            Claim.Display(
                                displayObject.name,
                                displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                            )
                        },
                    )
                }
            },
        )
    }
}

@Serializable
private data class W3CJsonLdCredentialDefinitionTO(
    @SerialName("@context") val context: List<String>,
    @SerialName("type") val types: List<String>,
    @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
) {

    fun toDomain(): W3CJsonLdCredentialDefinition = W3CJsonLdCredentialDefinition(
        context = context.map { URL(it) },
        type = types,
        credentialSubject = credentialSubject?.toDomain(),
    )
}

/**
 * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
 */
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
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("@context") @Required val context: List<String> = emptyList(),
    @SerialName("type") @Required val type: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: W3CJsonLdCredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
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
            context = context,
            type = type,
            credentialDefinition = credentialDefinition.toDomain(),
            order = order ?: emptyList(),
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
 */
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
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("@context") @Required val context: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: W3CJsonLdCredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
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
            context = context,
            credentialDefinition = credentialDefinition.toDomain(),
            order = order ?: emptyList(),
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
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
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
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
                credentialSubject = credentialSubject?.let { it.toDomain() },
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
            order = order ?: emptyList(),
        )
    }
}

/**
 * Unvalidated metadata of a Credential Issuer.
 */
@Serializable
private data class CredentialIssuerMetadataTO(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("authorization_servers") val authorizationServers: List<String>? = null,
    @SerialName("credential_endpoint") @Required val credentialEndpoint: String,
    @SerialName("batch_credential_endpoint") val batchCredentialEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("notification_endpoint") val notificationEndpoint: String? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionTO? = null,
    @SerialName("credential_identifiers_supported") val credentialIdentifiersSupported: Boolean = false,
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

        val batchCredentialEndpoint = batchCredentialEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidBatchCredentialEndpoint)
        }

        val deferredCredentialEndpoint = deferredCredentialEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidDeferredCredentialEndpoint)
        }
        val notificationEndpoint = notificationEndpoint?.let {
            CredentialIssuerEndpoint(it)
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidNotificationEndpoint)
        }

        ensure(credentialConfigurationsSupported.isNotEmpty()) { CredentialIssuerMetadataValidationError.CredentialsSupportedRequired }
        val credentialsSupported = credentialConfigurationsSupported.map { (id, credentialSupportedTO) ->
            val credentialId = CredentialConfigurationIdentifier(id)
            val credential = runCatching { credentialSupportedTO.toDomain() }
                .ensureSuccess(CredentialIssuerMetadataValidationError::InvalidCredentialsSupported)
            credentialId to credential
        }.toMap()

        val display = display?.map(DisplayTO::toDomain) ?: emptyList()

        return CredentialIssuerMetadata(
            credentialIssuerIdentifier,
            authorizationServers,
            credentialEndpoint,
            batchCredentialEndpoint,
            deferredCredentialEndpoint,
            notificationEndpoint,
            credentialResponseEncryption(),
            credentialIdentifiersSupported,
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

        return Display(
            name,
            locale?.let { Locale.forLanguageTag(it) },
            logo?.toLogo(),
            description,
            backgroundColor,
            textColor,
        )
    }
}

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
    @SerialName("mandatory") val mandatory: Boolean? = null,
    @SerialName("value_type") val valueType: String? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
) {
    fun toDomain(): Claim =
        Claim(
            mandatory = mandatory ?: false,
            valueType = valueType,
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
) {
    /**
     * Converts a [DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
     */
    fun toDomain(): CredentialIssuerMetadata.Display =
        CredentialIssuerMetadata.Display(name, locale)

    fun toClaimDisplay(): Claim.Display =
        Claim.Display(name, locale?.let { languageTag -> Locale.forLanguageTag(languageTag) })
}

private fun Map<String, ClaimTO>.toDomain(): Map<ClaimName, Claim?> =
    mapValues { (_, claim) -> claim.toDomain() }

private fun Map<String, ProofSigningAlgorithmsSupportedTO>?.toProofTypes(): ProofTypesSupported =
    when (this) {
        null -> ProofTypesSupported.Empty
        else -> {
            val values = map { (type, meta) -> proofTypeMeta(type, meta) }.toSet()
            ProofTypesSupported(values)
        }
    }

private fun proofTypeMeta(type: String, meta: ProofSigningAlgorithmsSupportedTO): ProofTypeMeta =
    when (type) {
        "jwt" -> ProofTypeMeta.Jwt(
            algorithms = meta.algorithms.map {
                require(it.isString) { "Expecting algorithm in string" }
                JWSAlgorithm.parse(it.content)
            },
        )

        "cwt" -> ProofTypeMeta.Cwt(
            algorithms = meta.cwtAlgorithms.map { CoseAlgorithm(it).getOrThrow() },
            curves = meta.cwtCurves.map { CoseCurve(it).getOrThrow() },
        )
        "ldp_vp" -> ProofTypeMeta.LdpVp
        else -> error("Unknown Proof Type '$type'")
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
