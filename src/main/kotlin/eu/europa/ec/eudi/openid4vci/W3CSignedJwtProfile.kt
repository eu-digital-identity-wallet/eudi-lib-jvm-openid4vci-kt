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

import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import java.util.*

object W3CSignedJwtProfile {

    const val FORMAT = "jwt_vc_json"

    /**
     * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
     */
    @Serializable
    data class CredentialSupportedTO(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported")
        override val cryptographicBindingMethodsSupported: List<String>? = null,
        @SerialName("cryptographic_suites_supported")
        override val cryptographicSuitesSupported: List<String>? = null,
        @SerialName("proof_types_supported")
        override val proofTypesSupported: List<String>? = null,
        @SerialName("display") override val display: List<DisplayTO>? = null,
        @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
        @SerialName("order") val order: List<String>? = null,
    ) : eu.europa.ec.eudi.openid4vci.CredentialSupportedTO {
        init {
            require(format == FORMAT) { "invalid format '$format'" }
        }

        @Serializable
        data class CredentialDefinitionTO(
            @SerialName("type") val types: List<String>,
            @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>?,
        )

        override fun toDomain(): eu.europa.ec.eudi.openid4vci.CredentialSupported {
            val bindingMethods =
                cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
                    ?: emptyList()
            val display = display?.map { it.toDomain() } ?: emptyList()
            val proofTypesSupported = proofTypesSupported.toProofTypes()
            val cryptographicSuitesSupported = cryptographicSuitesSupported ?: emptyList()

            return CredentialSupported(
                scope,
                bindingMethods,
                cryptographicSuitesSupported,
                proofTypesSupported,
                display,
                credentialDefinition.toDomain(),
                order ?: emptyList(),
            )
        }
    }

    fun CredentialSupportedTO.CredentialDefinitionTO.toDomain(): CredentialSupported.CredentialDefinition =
        CredentialSupported.CredentialDefinition(
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

    /**
     * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
     */
    data class CredentialSupported(
        override val scope: String? = null,
        override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
        override val cryptographicSuitesSupported: List<String> = emptyList(),
        override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
        override val display: List<Display> = emptyList(),
        val credentialDefinition: CredentialDefinition,
        val order: List<ClaimName> = emptyList(),
    ) : eu.europa.ec.eudi.openid4vci.CredentialSupported {

        data class CredentialDefinition(
            val type: List<String>,
            val credentialSubject: Map<ClaimName, Claim?>?,
        )
    }

    @Serializable
    data class CredentialMetadataTO(
        @SerialName("format") @Required val format: String,
        @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinition,
    ) {
        @Serializable
        data class CredentialDefinition(
            @SerialName("type") val type: List<String>,
        )
    }

    /**
     * A signed JWT (not using JSON-LD) credential metadata object.
     */
    data class CredentialMetadata(
        val credentialDefinition: CredentialDefinitionMetadata,
        val scope: String? = null,
    ) : eu.europa.ec.eudi.openid4vci.CredentialMetadata.ByProfile {
        data class CredentialDefinitionMetadata(
            val type: List<String>,
        )
    }

    fun matchSupportedAndToDomain(jsonObject: JsonObject, metadata: CredentialIssuerMetadata): CredentialMetadata {
        val credentialDefinition = Json.decodeFromJsonElement<CredentialMetadataTO>(
            jsonObject,
        ).credentialDefinition

        fun fail(): Nothing =
            throw IllegalArgumentException(
                "Unsupported W3CVerifiableCredential with format '$FORMAT' and credentialDefinition '$credentialDefinition'",
            )

        return metadata.credentialsSupported
            .firstOrNull {
                it is CredentialSupported && it.credentialDefinition.type == credentialDefinition.type
            }
            ?.let {
                CredentialMetadata(
                    CredentialMetadata.CredentialDefinitionMetadata(
                        type = credentialDefinition.type,
                    ),
                    it.scope,
                )
            }
            ?: fail()
    }

    data class ClaimSet(
        val claims: Map<ClaimName, Claim>,
    ) : eu.europa.ec.eudi.openid4vci.ClaimSet
}
