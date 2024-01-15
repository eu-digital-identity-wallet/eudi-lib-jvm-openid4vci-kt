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
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import eu.europa.ec.eudi.openid4vci.internal.ensure
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
    val cryptographicSuitesSupported: List<String>?
    val proofTypesSupported: List<String>?
    val display: List<CredentialSupportedDisplayTO>?
}

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
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
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
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_SD_JWT_VC) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("type") val type: String,
        @SerialName("claims") val claims: Map<String, ClaimTO>? = null,
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
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("@context") @Required val context: List<String> = emptyList(),
    @SerialName("type") @Required val type: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_W3C_JSONLD_DATA_INTEGRITY) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("@context") val context: List<String>,
        @SerialName("type") val types: List<String>,
        @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
    )
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
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("@context") @Required val context: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
) : CredentialSupportedTO {
    init {
        require(format == FORMAT_W3C_JSONLD_SIGNED_JWT) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("@context") val context: List<String>,
        @SerialName("type") val types: List<String>,
        @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
    )
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
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
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
    @SerialName("credential_response_encryption_alg_values_supported")
    val credentialResponseEncryptionAlgorithmsSupported: List<String>? = null,
    @SerialName("credential_response_encryption_enc_values_supported")
    val credentialResponseEncryptionMethodsSupported: List<String>? = null,
    @SerialName("require_credential_response_encryption")
    val requireCredentialResponseEncryption: Boolean? = null,
    @SerialName("credential_identifiers_supported")
    val credentialIdentifiersSupported: Boolean? = null,
    @SerialName("credentials_supported") val credentialsSupported: Map<String, CredentialSupportedTO> = emptyMap(),
    @SerialName("display") val display: List<DisplayTO>? = null,
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
    @SerialName("url") val url: String? = null,
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
    val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
        .getOrThrowAs { CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId(it) }

    val authorizationServers = authorizationServers
        ?.let { servers -> servers.map { HttpsUrl(it).getOrThrowAs(CredentialIssuerMetadataValidationError::InvalidAuthorizationServer) } }
        ?: listOf(credentialIssuerIdentifier.value)

    val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
        .getOrThrowAs(CredentialIssuerMetadataValidationError::InvalidCredentialEndpoint)

    val batchCredentialEndpoint = batchCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(CredentialIssuerMetadataValidationError::InvalidBatchCredentialEndpoint) }

    val deferredCredentialEndpoint = deferredCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(CredentialIssuerMetadataValidationError::InvalidDeferredCredentialEndpoint) }

    val credentialsSupported = try {
        credentialsSupported.map {
            CredentialIdentifier(it.key) to it.value.toDomain()
        }.toMap()
    } catch (it: Throwable) {
        throw CredentialIssuerMetadataValidationError.InvalidCredentialsSupported(it)
    }
    ensure(credentialsSupported.isNotEmpty()) { CredentialIssuerMetadataValidationError.CredentialsSupportedRequired }

    val display = display?.map { it.toDomain() } ?: emptyList()

    return CredentialIssuerMetadata(
        credentialIssuerIdentifier,
        authorizationServers,
        credentialEndpoint,
        batchCredentialEndpoint,
        deferredCredentialEndpoint,
        credentialResponseEncryption(),
        credentialIdentifiersSupported ?: false,
        credentialsSupported,
        display,
    )
}

private fun CredentialSupportedTO.toDomain(): CredentialSupported = when (this) {
    is MsdMdocCredentialTO -> credentialSupportedFromJson(this)
    is SdJwtVcCredentialTO -> credentialSupportedFromJson(this)
    is W3CJsonLdDataIntegrityCredentialTO -> credentialSupportedFromJson(this)
    is W3CJsonLdSignedJwtCredentialTO -> credentialSupportedFromJson(this)
    is W3CSignedJwtCredentialTO -> credentialSupportedFromJson(this)
}

private fun credentialSupportedFromJson(csJson: MsdMdocCredentialTO): MsoMdocCredential {
    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    fun claims(): MsoMdocClaims = csJson.claims?.mapValues { (_, claims) ->
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
        csJson.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        csJson.docType,
        claims(),
        csJson.order ?: emptyList(),
    )
}

private fun credentialSupportedFromJson(csJson: SdJwtVcCredentialTO): SdJwtVcCredential {
    fun SdJwtVcCredentialTO.CredentialDefinitionTO.toDomain(): SdJwtVcCredential.CredentialDefinition =
        SdJwtVcCredential.CredentialDefinition(
            type = type,
            claims = claims?.mapValues { nameAndClaim ->
                nameAndClaim.value.let {
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

    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return SdJwtVcCredential(
        csJson.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        csJson.credentialDefinition.toDomain(),
    )
}

private fun credentialSupportedFromJson(
    csJson: W3CJsonLdDataIntegrityCredentialTO,
): W3CJsonLdDataIntegrityCredential {
    fun toDomain(
        credentialDefinitionTO: W3CJsonLdDataIntegrityCredentialTO.CredentialDefinitionTO,
    ): W3CJsonLdDataIntegrityCredential.CredentialDefinition =
        W3CJsonLdDataIntegrityCredential.CredentialDefinition(
            context = credentialDefinitionTO.context.map { URL(it) },
            type = credentialDefinitionTO.types,
            credentialSubject = credentialDefinitionTO.credentialSubject?.mapValues { nameAndClaim ->
                nameAndClaim.value.let {
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

    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CJsonLdDataIntegrityCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        cryptographicSuitesSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        context = csJson.context,
        type = csJson.type,
        credentialDefinition = toDomain(csJson.credentialDefinition),
        order = csJson.order ?: emptyList(),
    )
}

private fun credentialSupportedFromJson(csJson: W3CJsonLdSignedJwtCredentialTO): W3CJsonLdSignedJwtCredential {
    fun W3CJsonLdSignedJwtCredentialTO.CredentialDefinitionTO.toDomain(): W3CJsonLdSignedJwtCredential.CredentialDefinition =
        W3CJsonLdSignedJwtCredential.CredentialDefinition(
            context = context.map { URL(it) },
            type = types,
            credentialSubject = credentialSubject?.mapValues { nameAndClaim ->
                nameAndClaim.value.let {
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

    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CJsonLdSignedJwtCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        cryptographicSuitesSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        context = csJson.context,
        credentialDefinition = csJson.credentialDefinition.toDomain(),
        order = csJson.order ?: emptyList(),
    )
}

private fun credentialSupportedFromJson(csJson: W3CSignedJwtCredentialTO): W3CSignedJwtCredential {
    fun W3CSignedJwtCredentialTO.CredentialDefinitionTO.toDomain(): W3CSignedJwtCredential.CredentialDefinition =
        W3CSignedJwtCredential.CredentialDefinition(
            type = types,
            credentialSubject = credentialSubject?.mapValues { nameAndClaim ->
                nameAndClaim.value.let {
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

    val bindingMethods = csJson.cryptographicBindingMethodsSupported
        ?.map { cryptographicBindingMethodOf(it) }
        ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CSignedJwtCredential(
        scope = csJson.scope,
        cryptographicBindingMethodsSupported = bindingMethods,
        cryptographicSuitesSupported = cryptographicSuitesSupported,
        proofTypesSupported = proofTypesSupported,
        display = display,
        credentialDefinition = csJson.credentialDefinition.toDomain(),
        order = csJson.order ?: emptyList(),
    )
}

private fun CredentialIssuerMetadataTO.credentialResponseEncryption(): CredentialResponseEncryption {
    val requireEncryption = requireCredentialResponseEncryption ?: false
    val encryptionAlgorithms = credentialResponseEncryptionAlgorithmsSupported
        ?.map { JWEAlgorithm.parse(it) }
        ?: emptyList()
    val encryptionMethods = credentialResponseEncryptionMethodsSupported
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
        require(encryptionAlgorithms.isEmpty())
        require(encryptionMethods.isEmpty())
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
            url?.let { HttpsUrl(it).getOrThrow() },
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
private fun List<String>?.toProofTypes(): List<ProofType> =
    this?.map { proofTypeOf(it) } ?: listOf(ProofType.JWT)

private fun proofTypeOf(s: String): ProofType = when (s) {
    "jwt" -> ProofType.JWT
    "cwt" -> ProofType.CWT
    else -> error("Unknown Proof Type '$s'")
}

/**
 * Utility method to convert a list of string to a list of [CryptographicBindingMethod].
 */
private fun cryptographicBindingMethodOf(s: String): CryptographicBindingMethod =
    when {
        s == "jwk" -> CryptographicBindingMethod.JWK
        s == "cose_key" -> CryptographicBindingMethod.COSE
        s == "mso" -> CryptographicBindingMethod.MSO
        s.startsWith("did") -> CryptographicBindingMethod.DID(s)
        else -> error("Unknown Cryptographic Binding Method '$s'")
    }

private fun <T> Result<T>.getOrThrowAs(f: (Throwable) -> Throwable): T =
    fold(onSuccess = { it }, onFailure = { throw f(it) })
