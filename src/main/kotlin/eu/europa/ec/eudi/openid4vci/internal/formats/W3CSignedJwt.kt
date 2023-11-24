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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import java.util.*

internal data object W3CSignedJwt : Format<
    W3CSignedJwt.Model.CredentialMetadata,
    W3CSignedJwt.Model.CredentialSupported,
    W3CSignedJwt.Model.CredentialIssuanceRequest,
    > {

    const val FORMAT = "jwt_vc_json"

    override fun matchSupportedCredentialByTypeAndMapToDomain(
        jsonObject: JsonObject,
        issuerMetadata: CredentialIssuerMetadata,
    ): Model.CredentialMetadata {
        val credentialDefinition = Json.decodeFromJsonElement<Model.CredentialMetadataTO>(
            jsonObject,
        ).credentialDefinition

        fun fail(): Nothing =
            throw IllegalArgumentException(
                "Unsupported W3CVerifiableCredential with format '$FORMAT' and credentialDefinition '$credentialDefinition'",
            )

        return issuerMetadata.credentialsSupported
            .filterIsInstance<Model.CredentialSupported>()
            .firstOrNull { it.credentialDefinition.type == credentialDefinition.type }
            ?.let {
                Model.CredentialMetadata(
                    Model.CredentialMetadata.CredentialDefinitionMetadata(
                        type = credentialDefinition.type,
                    ),
                    it.scope,
                )
            }
            ?: fail()
    }

    override fun matchSupportedCredentialByType(
        metadata: Model.CredentialMetadata,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported =
        issuerMetadata.credentialsSupported.firstOrNull {
            it is Model.CredentialSupported &&
                it.credentialDefinition.type == metadata.credentialDefinition.type
        } ?: error("Issuer does not support issuance of credential : $metadata")

    override fun constructIssuanceRequest(
        supportedCredential: Model.CredentialSupported,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    object Model {
        /**
         * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
         */
        @Serializable
        @SerialName(FORMAT)
        data class CredentialSupportedTO(
            @SerialName("format") @Required override val format: String = FORMAT,
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
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupportedTO {
            init {
                require(format == FORMAT) { "invalid format '$format'" }
            }

            @Serializable
            data class CredentialDefinitionTO(
                @SerialName("type") val types: List<String>,
                @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
            )

            override fun toDomain(): eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported {
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
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported {

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
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialMetadata.ByFormat {
            data class CredentialDefinitionMetadata(
                val type: List<String>,
            )
        }

        data class ClaimSet(
            val claims: Map<ClaimName, Claim>,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.ClaimSet

        class CredentialIssuanceRequest(
            override val format: String,
            override val proof: Proof?,
            override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential {

            override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO {
                TODO("Not yet implemented")
            }
        }
    }
}
