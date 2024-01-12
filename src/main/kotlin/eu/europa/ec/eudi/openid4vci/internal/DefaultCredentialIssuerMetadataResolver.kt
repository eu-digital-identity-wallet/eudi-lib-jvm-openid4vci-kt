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
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.*
import eu.europa.ec.eudi.openid4vci.internal.formats.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator
import java.net.URL
import java.util.*

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
internal class DefaultCredentialIssuerMetadataResolver(
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> = coroutineScope {
        runCatching {
            val credentialIssuerMetadataContent = try {
                val url =
                    URLBuilder(issuer.toString())
                        .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
                        .build()
                        .toURI()
                        .toURL()

                ktorHttpClientFactory().use { client -> client.get(url).body<String>() }
            } catch (t: Throwable) {
                throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
            }
            val metaData = parseMetaData(credentialIssuerMetadataContent)
            if (metaData.credentialIssuerIdentifier != issuer) {
                throw InvalidCredentialIssuerId(
                    IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                )
            }
            metaData
        }
    }
}

private fun parseMetaData(json: String): CredentialIssuerMetadata {
    val credentialIssuerMetadataObject = try {
        JsonSupport.decodeFromString<CredentialIssuerMetadataTO>(json)
    } catch (t: Throwable) {
        throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(t)
    }
    return credentialIssuerMetadataObject.toDomain().getOrThrow()
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
@SerialName(MsoMdoc.FORMAT)
private data class MsdMdocCredentialTO(
    @SerialName("format") @Required override val format: String = MsoMdoc.FORMAT,
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
        require(format == MsoMdoc.FORMAT) { "invalid format '$format'" }
    }
}

@Serializable
@SerialName(SdJwtVc.FORMAT)
private data class SdJwtVcCredentialTO(
    @SerialName("format") @Required override val format: String = SdJwtVc.FORMAT,
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
        require(format == SdJwtVc.FORMAT) { "invalid format '$format'" }
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
@SerialName(W3CJsonLdDataIntegrity.FORMAT)
private data class W3CJsonLdDataIntegrityCredentialTO(
    @SerialName("format") @Required override val format: String = W3CJsonLdDataIntegrity.FORMAT,
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
        require(format == W3CJsonLdDataIntegrity.FORMAT) { "invalid format '$format'" }
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
@SerialName(W3CJsonLdSignedJwt.FORMAT)
private data class W3CJsonLdSignedJwtCredentialTO(
    @SerialName("format") @Required override val format: String = W3CJsonLdSignedJwt.FORMAT,
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
        require(format == W3CJsonLdSignedJwt.FORMAT) { "invalid format '$format'" }
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
@SerialName(W3CSignedJwt.FORMAT)
private data class W3CSignedJwtCredentialTO(
    @SerialName("format") @Required override val format: String = W3CSignedJwt.FORMAT,
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
        require(format == W3CSignedJwt.FORMAT) { "invalid format '$format'" }
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
private fun CredentialIssuerMetadataTO.toDomain(): Result<CredentialIssuerMetadata> = runCatching {
    val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
        .getOrThrowAs { InvalidCredentialIssuerId(it) }

    val authorizationServers = authorizationServers
        ?.let { servers -> servers.map { HttpsUrl(it).getOrThrowAs(::InvalidAuthorizationServer) } }
        ?: listOf(credentialIssuerIdentifier.value)

    val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
        .getOrThrowAs(::InvalidCredentialEndpoint)

    val batchCredentialEndpoint = batchCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(::InvalidBatchCredentialEndpoint) }

    val deferredCredentialEndpoint = deferredCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(::InvalidDeferredCredentialEndpoint) }

    val credentialsSupported = try {
        credentialsSupported.map {
            CredentialIdentifier(it.key) to it.value.toDomain()
        }.toMap()
    } catch (it: Throwable) {
        throw InvalidCredentialsSupported(it)
    }.apply {
        ifEmpty { throw CredentialsSupportedRequired }
    }

    val display = display?.map { it.toDomain() } ?: emptyList()

    CredentialIssuerMetadata(
        credentialIssuerIdentifier,
        authorizationServers,
        credentialEndpoint,
        batchCredentialEndpoint,
        deferredCredentialEndpoint,
        credentialResponseEncryption().getOrThrow(),
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
        ?.toCryptographicBindingMethods()
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

    val bindingMethods =
        csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
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

    val bindingMethods =
        csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
            ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CJsonLdDataIntegrityCredential(
        csJson.scope, bindingMethods, cryptographicSuitesSupported, proofTypesSupported,
        display, csJson.context, csJson.type, toDomain(csJson.credentialDefinition),
        csJson.order ?: emptyList(),
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

    val bindingMethods =
        csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
            ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CJsonLdSignedJwtCredential(
        csJson.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        csJson.context,
        csJson.credentialDefinition.toDomain(),
        csJson.order ?: emptyList(),
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

    val bindingMethods =
        csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
            ?: emptyList()
    val display = csJson.display?.map { it.toDomain() } ?: emptyList()
    val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
    val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

    return W3CSignedJwtCredential(
        csJson.scope,
        bindingMethods,
        cryptographicSuitesSupported,
        proofTypesSupported,
        display,
        csJson.credentialDefinition.toDomain(),
        csJson.order ?: emptyList(),
    )
}

private fun CredentialIssuerMetadataTO.credentialResponseEncryption(): Result<CredentialResponseEncryption> =
    runCatching {
        val requireEncryption = requireCredentialResponseEncryption ?: false
        val encryptionAlgorithms = credentialResponseEncryptionAlgorithmsSupported
            ?.map { JWEAlgorithm.parse(it) }
            ?: emptyList()
        val encryptionMethods = credentialResponseEncryptionMethodsSupported
            ?.map { EncryptionMethod.parse(it) }
            ?: emptyList()

        if (requireEncryption) {
            if (encryptionAlgorithms.isEmpty()) {
                throw CredentialResponseEncryptionAlgorithmsRequired
            }
            val allAreAsymmetricAlgorithms = encryptionAlgorithms.all {
                JWEAlgorithm.Family.ASYMMETRIC.contains(it)
            }
            if (!allAreAsymmetricAlgorithms) {
                throw CredentialResponseAsymmetricEncryptionAlgorithmsRequired
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
 * Utility method to convert a list of string to a list of [CryptographicBindingMethod].
 */
private fun List<String>.toCryptographicBindingMethods(): List<CryptographicBindingMethod> =
    map {
        when (it) {
            "jwk" -> CryptographicBindingMethod.JWK
            "cose_key" -> CryptographicBindingMethod.COSE
            "mso" -> CryptographicBindingMethod.MSO
            else ->
                if (it.startsWith("did")) {
                    CryptographicBindingMethod.DID(it)
                } else {
                    error("Unknown Cryptographic Binding Method '$it'")
                }
        }
    }

/**
 * Utility method to convert a list of string to a list of [ProofType].
 */
private fun List<String>?.toProofTypes(): List<ProofType> =
    this?.map {
        when (it) {
            "jwt" -> ProofType.JWT
            "cwt" -> ProofType.CWT
            else -> error("Unknown Proof Type '$it'")
        }
    } ?: emptyList<ProofType>()
        .ifEmpty {
            listOf(ProofType.JWT)
        }

/**
 * Converts a [DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
 */
private fun DisplayTO.toDomain(): CredentialIssuerMetadata.Display =
    CredentialIssuerMetadata.Display(name, locale)

private fun <T> Result<T>.getOrThrowAs(f: (Throwable) -> Throwable): T =
    fold(onSuccess = { it }, onFailure = { throw f(it) })

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
