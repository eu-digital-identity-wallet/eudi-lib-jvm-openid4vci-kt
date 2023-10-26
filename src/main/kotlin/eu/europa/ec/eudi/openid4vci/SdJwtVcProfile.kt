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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import java.util.*

object SdJwtVcProfile {

    const val FORMAT = "vc+sd-jwt"

    @Serializable
    data class CredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported")
        override val cryptographicBindingMethodsSupported: List<String>? = null,
        @SerialName("cryptographic_suites_supported")
        override val cryptographicSuitesSupported: List<String>? = null,
        @SerialName("proof_types_supported")
        override val proofTypesSupported: List<String>? = null,
        @SerialName("display") override val display: List<DisplayTO>? = null,
        @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionObject,
    ) : CredentialSupportedTO {
        init {
            require(format == FORMAT) { "invalid format '$format'" }
        }

        @Serializable
        data class CredentialDefinitionObject(
            @SerialName("type") val type: String,
            @SerialName("claims") val claims: Map<String, ClaimTO>?,
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
            )
        }
    }

    private fun CredentialSupportedObject.CredentialDefinitionObject.toDomain(): CredentialSupported.CredentialDefinition =
        CredentialSupported.CredentialDefinition(
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

    data class CredentialSupported(
        override val scope: String? = null,
        override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
        override val cryptographicSuitesSupported: List<String> = emptyList(),
        override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
        override val display: List<Display> = emptyList(),
        val credentialDefinition: CredentialDefinition,
    ) : eu.europa.ec.eudi.openid4vci.CredentialSupported {
        data class CredentialDefinition(
            val type: String,
            val claims: Map<ClaimName, Claim?>?,
        )
    }

    @Serializable
    data class CredentialMetadataObject(
        @SerialName("format") @Required val format: String,
        @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinition,
    ) {
        @Serializable
        data class CredentialDefinition(
            @SerialName("type") val type: String,
        )
    }

    data class CredentialMetadata(
        val type: String,
        val scope: String? = null,
    ) : eu.europa.ec.eudi.openid4vci.CredentialMetadata.ByProfile

    fun matchSupportedAndToDomain(jsonObject: JsonObject, metadata: CredentialIssuerMetadata): CredentialMetadata {
        val credentialDefinition = Json.decodeFromJsonElement<CredentialMetadataObject>(
            jsonObject,
        ).credentialDefinition

        fun fail(): Nothing =
            throw IllegalArgumentException("Unsupported metadata with format $FORMAT' and type '${credentialDefinition.type}'")

        return metadata.credentialsSupported
            .firstOrNull {
                it is CredentialSupported && it.credentialDefinition.type == credentialDefinition.type
            }
            ?.let {
                CredentialMetadata(credentialDefinition.type, (it as CredentialSupported).scope)
            }
            ?: fail()
    }

    class CredentialIssuanceRequest private constructor(
        override val proof: Proof? = null,
        override val credentialEncryptionJwk: JWK? = null,
        override val credentialResponseEncryptionAlg: JWEAlgorithm? = null,
        override val credentialResponseEncryptionMethod: EncryptionMethod? = null,
        val credentialDefinition: CredentialDefinition,
    ) : eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequest.SingleCredential {

        override val format: String = FORMAT

        data class CredentialDefinition(
            val type: String,
            val claims: ClaimSet.SdJwtVc?,
        )

        companion object {
            operator fun invoke(
                type: String,
                proof: Proof? = null,
                credentialEncryptionJwk: JWK? = null,
                credentialResponseEncryptionAlg: JWEAlgorithm? = null,
                credentialResponseEncryptionMethod: EncryptionMethod? = null,
                claimSet: ClaimSet.SdJwtVc? = null,
            ): Result<CredentialIssuanceRequest> = runCatching {
                var encryptionMethod = credentialResponseEncryptionMethod
                if (credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null) {
                    encryptionMethod = EncryptionMethod.A256GCM
                } else if (credentialResponseEncryptionAlg != null && credentialEncryptionJwk == null) {
                    throw CredentialIssuanceError.InvalidIssuanceRequest("Encryption algorithm was provided but no encryption key")
                        .asException()
                } else if (credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null) {
                    throw CredentialIssuanceError.InvalidIssuanceRequest(
                        "Credential response encryption algorithm must be specified if Credential " +
                            "response encryption method is provided",
                    ).asException()
                }

                CredentialIssuanceRequest(
                    proof = proof,
                    credentialEncryptionJwk = credentialEncryptionJwk,
                    credentialResponseEncryptionAlg = credentialResponseEncryptionAlg,
                    credentialResponseEncryptionMethod = encryptionMethod,
                    credentialDefinition = CredentialDefinition(
                        type = type,
                        claims = claimSet,
                    ),
                )
            }
        }
    }

    @Serializable
    @OptIn(ExperimentalSerializationApi::class)
    @JsonClassDiscriminator("format")
    data class CredentialIssuanceRequestTO(
        @SerialName("format") override val format: String,
        @SerialName("proof") override val proof: JsonObject?,
        @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject?,
        @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String?,
        @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String?,
        @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO,
    ) : eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequestTO.SingleCredentialTO {

        @Serializable
        data class CredentialDefinitionTO(
            @SerialName("type") val type: String,
            @SerialName("claims") val claims: JsonObject?,
        )
    }
}
