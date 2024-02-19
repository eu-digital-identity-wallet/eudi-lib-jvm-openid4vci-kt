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
package eu.europa.ec.eudi.openid4vci.internal.formats

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
    val credentialSigningAlgorithmsSupported: List<String>?
    val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>?
    val display: List<CredentialSupportedDisplayTO>?
}

@Serializable
private data class ProofSigningAlgorithmsSupportedTO(
    @SerialName("proof_signing_alg_values_supported") @Required val algorithms: List<String>,
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
    override val credentialSigningAlgorithmsSupported: List<String>? = null,
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
}

@Serializable
@SerialName(FORMAT_SD_JWT_VC)
private data class SdJwtVcCredentialTO(
    @SerialName("format") @Required override val format: String = FORMAT_SD_JWT_VC,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("credential_signing_alg_values_supported")
    override val credentialSigningAlgorithmsSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: Map<String, ProofSigningAlgorithmsSupportedTO>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("vct") val type: String,
    @SerialName("claims") val claims: Map<String, ClaimTO>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_SD_JWT_VC) { "invalid format '$format'" }
    }
}

@Serializable
private data class W3CJsonLdCredentialDefinitionTO(
    @SerialName("@context") val context: List<String>,
    @SerialName("type") val types: List<String>,
    @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
)

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
    override val credentialSigningAlgorithmsSupported: List<String>? = null,
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
    override val credentialSigningAlgorithmsSupported: List<String>? = null,
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
    override val credentialSigningAlgorithmsSupported: List<String>? = null,
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
    )
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
    @SerialName("credential_configurations_supported") val credentialsSupported: Map<String, CredentialSupportedTO> = emptyMap(),
    @SerialName("display") val display: List<DisplayTO>? = null,
)

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
internal data class CredentialSupportedDisplayTO(
    @SerialName("name") @Required val name: String,
    @SerialName("locale") val locale: String? = null,
    @SerialName("logo") val logo: LogoObject? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * Logo information.
 */
@Serializable
internal data class LogoObject(
    @SerialName("uri") val uri: String? = null,
    @SerialName("alt_text") val alternativeText: String? = null,
)

/**
 * The details of a Claim.
 */
@Serializable
internal data class ClaimTO(
    @SerialName("mandatory") val mandatory: Boolean? = null,
    @SerialName("value_type") val valueType: String? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
)

/**
 * Display properties of a Claim.
 */
@Serializable
internal data class DisplayTO(
    @SerialName("name") val name: String? = null,
    @SerialName("locale") val locale: String? = null,
)

/**
 * Converts and validates  a [CredentialIssuerMetadataTO] as a [CredentialIssuerMetadata] instance.
 */
private fun CredentialIssuerMetadataTO.toDomain(): CredentialIssuerMetadata {
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

    ensure(credentialsSupported.isNotEmpty()) { CredentialIssuerMetadataValidationError.CredentialsSupportedRequired }
    val credentialsSupported = credentialsSupported.map { (id, credentialSupportedTO) ->
        val credentialId = CredentialIdentifier(id)
        val credential = credentialSupportedTO.toDomain()
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
        credentialResponseEncryption(),
        credentialIdentifiersSupported,
        credentialsSupported,
        display,
    )
}

private fun CredentialSupportedTO.toDomain(): Result<CredentialSupported> = runCatching {
    when (this) {
        is MsdMdocCredentialTO -> credentialSupportedFromTransferObject(this)
        is SdJwtVcCredentialTO -> credentialSupportedFromTransferObject(this)
        is W3CJsonLdDataIntegrityCredentialTO -> credentialSupportedFromTransferObject(this)
        is W3CJsonLdSignedJwtCredentialTO -> credentialSupportedFromTransferObject(this)
        is W3CSignedJwtCredentialTO -> credentialSupportedFromTransferObject(this)
    }
}

private fun credentialSupportedFromTransferObject(transferObject: MsdMdocCredentialTO): MsoMdocCredential {
    val bindingMethods = transferObject.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = transferObject.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = transferObject.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = transferObject.credentialSigningAlgorithmsSupported ?: emptyList()

    fun claims(): MsoMdocClaims = transferObject.claims?.mapValues { (_, claims) ->
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
    } ?: emptyMap()

    return MsoMdocCredential(
        transferObject.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        transferObject.docType,
        claims(),
        transferObject.order ?: emptyList(),
    )
}

private fun credentialSupportedFromTransferObject(csJson: SdJwtVcCredentialTO): SdJwtVcCredential {
    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.credentialSigningAlgorithmsSupported ?: emptyList()

    return SdJwtVcCredential(
        csJson.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        csJson.type,
        csJson.claims?.mapValues { (_, claim) ->
            claim.let {
                Claim(
                    it.mandatory ?: false,
                    it.valueType,
                    it.display?.map { displayObject ->
                        Claim.Display(
                            displayObject.name,
                            displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                        )
                    } ?: emptyList(),
                )
            }
        },
    )
}

private fun toDomain(
    credentialDefinitionTO: W3CJsonLdCredentialDefinitionTO,
): W3CJsonLdCredentialDefinition = W3CJsonLdCredentialDefinition(
    context = credentialDefinitionTO.context.map { URL(it) },
    type = credentialDefinitionTO.types,
    credentialSubject = credentialDefinitionTO.credentialSubject?.let { toDomain(it) },
)

private fun toDomain(ms: Map<String, ClaimTO>): Map<ClaimName, Claim?> =
    ms.mapValues { (_, claim) -> toDomain(claim) }

private fun toDomain(it: ClaimTO): Claim =
    Claim(
        it.mandatory ?: false,
        it.valueType,
        it.display?.map { displayObject ->
            Claim.Display(
                displayObject.name,
                displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
            )
        } ?: emptyList(),
    )

private fun credentialSupportedFromTransferObject(
    csJson: W3CJsonLdDataIntegrityCredentialTO,
): W3CJsonLdDataIntegrityCredential {
    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.credentialSigningAlgorithmsSupported ?: emptyList()

    return W3CJsonLdDataIntegrityCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        context = csJson.context,
        type = csJson.type,
        credentialDefinition = toDomain(csJson.credentialDefinition),
        order = csJson.order ?: emptyList(),
    )
}

private fun credentialSupportedFromTransferObject(csJson: W3CJsonLdSignedJwtCredentialTO): W3CJsonLdSignedJwtCredential {
    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.credentialSigningAlgorithmsSupported ?: emptyList()

    return W3CJsonLdSignedJwtCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        context = csJson.context,
        credentialDefinition = toDomain(csJson.credentialDefinition),
        order = csJson.order ?: emptyList(),
    )
}

private fun credentialSupportedFromTransferObject(csJson: W3CSignedJwtCredentialTO): W3CSignedJwtCredential {
    fun W3CSignedJwtCredentialTO.CredentialDefinitionTO.toDomain(): W3CSignedJwtCredential.CredentialDefinition =
        W3CSignedJwtCredential.CredentialDefinition(
            type = types,
            credentialSubject = credentialSubject?.let { toDomain(it) },
        )

    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.credentialSigningAlgorithmsSupported ?: emptyList()

    return W3CSignedJwtCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        credentialSigningAlgorithmsSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        credentialDefinition = csJson.credentialDefinition.toDomain(),
        order = csJson.order ?: emptyList(),
    )
}

private fun CredentialIssuerMetadataTO.credentialResponseEncryption(): CredentialResponseEncryption {
    val requireEncryption = credentialResponseEncryption?.encryptionRequired ?: false
    val encryptionAlgorithms = credentialResponseEncryption?.algorithmsSupported
        ?.map { JWEAlgorithm.parse(it) }
        ?: emptyList()
    val encryptionMethods = credentialResponseEncryption?.methodsSupported
        ?.map { EncryptionMethod.parse(it) }
        ?: emptyList()

    return if (requireEncryption) {
        if (encryptionAlgorithms.isEmpty()) {
            throw CredentialIssuerMetadataValidationError.CredentialResponseEncryptionAlgorithmsRequired
        }
        val allAreAsymmetricAlgorithms = encryptionAlgorithms.all {
            JWEAlgorithm.Family.ASYMMETRIC.contains(it)
        }
        if (!allAreAsymmetricAlgorithms) {
            throw CredentialIssuerMetadataValidationError.CredentialResponseAsymmetricEncryptionAlgorithmsRequired
        }

        CredentialResponseEncryption.Required(
            encryptionAlgorithms,
            encryptionMethods,
        )
    } else {
        CredentialResponseEncryption.NotRequired
    }
}

/**
 * Converts a [DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
 */
private fun DisplayTO.toDomain(): CredentialIssuerMetadata.Display =
    CredentialIssuerMetadata.Display(name, locale)

/**
 * Utility method to convert a [CredentialSupportedDisplayTO] transfer object to the respective [Display] domain object.
 */
private fun CredentialSupportedDisplayTO.toDomain(): Display {
    fun LogoObject.toLogo(): Display.Logo =
        Display.Logo(
            uri?.let { HttpsUrl(it).getOrThrow() },
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

/**
 * Utility method to convert a list of string to a list of [ProofType].
 */
private fun Map<String, ProofSigningAlgorithmsSupportedTO>?.toProofTypes(): Map<ProofType, List<JWSAlgorithm>> =
    this?.map {
        proofTypeOf(it.key) to it.value.algorithms.map { s -> JWSAlgorithm.parse(s) }
    }?.toMap() ?: emptyMap()

private fun proofTypeOf(s: String): ProofType = when (s) {
    "jwt" -> ProofType.JWT
    "cwt" -> ProofType.CWT
    "ldp_vp" -> ProofType.LDP_VP
    else -> error("Unknown Proof Type '$s'")
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
