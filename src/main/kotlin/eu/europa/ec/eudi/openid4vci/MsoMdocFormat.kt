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
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import java.util.*

object MsoMdocFormat {

    const val FORMAT = "mso_mdoc"

    /**
     * The data of a Verifiable Credentials issued as an ISO mDL.
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
        @SerialName("doctype") @Required val docType: String,
        @SerialName("claims") val claims: Map<String, Map<String, ClaimTO>>? = null,
        @SerialName("order") val order: List<String>? = null,
    ) : eu.europa.ec.eudi.openid4vci.CredentialSupportedTO {
        init {
            require(format == FORMAT) { "invalid format '$format'" }
        }

        override fun toDomain(): CredentialSupported {
            val bindingMethods =
                cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
                    ?: emptyList()
            val display = display?.map { it.toDomain() } ?: emptyList()
            val proofTypesSupported = proofTypesSupported.toProofTypes()
            val cryptographicSuitesSupported = cryptographicSuitesSupported ?: emptyList()

            fun claims(): MsoMdocClaims =
                claims?.mapValues { namespaceAndClaims ->
                    namespaceAndClaims.value.mapValues { claimNameAndClaim ->
                        claimNameAndClaim.value.let { claimObject ->
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

            return CredentialSupported(
                scope,
                bindingMethods,
                cryptographicSuitesSupported,
                proofTypesSupported,
                display,
                docType,
                claims(),
                order ?: emptyList(),
            )
        }
    }

    /**
     * The data of a Verifiable Credentials issued as an ISO mDL.
     */
    data class CredentialSupported(
        override val scope: String? = null,
        override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
        override val cryptographicSuitesSupported: List<String> = emptyList(),
        override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
        override val display: List<Display> = emptyList(),
        val docType: String,
        val claims: MsoMdocClaims = emptyMap(),
        val order: List<ClaimName> = emptyList(),
    ) : eu.europa.ec.eudi.openid4vci.CredentialSupported

    @Serializable
    data class CredentialMetadataTO(
        @SerialName("format") @Required val format: String,
        @SerialName("doctype") @Required val docType: String,
    )

    /**
     * An MSO MDOC credential metadata object.
     */
    data class CredentialMetadata(
        val docType: String,
        val scope: String? = null,
    ) : eu.europa.ec.eudi.openid4vci.CredentialMetadata.ByFormat

    fun matchSupportedAndToDomain(jsonObject: JsonObject, metadata: CredentialIssuerMetadata): CredentialMetadata {
        val docType = Json.decodeFromJsonElement<CredentialMetadataTO>(jsonObject).docType
        return metadata.credentialsSupported
            .firstOrNull { it is CredentialSupported && it.docType == docType }
            ?.let { CredentialMetadata(docType, (it as CredentialSupported).scope) }
            ?: error("Unsupported MsoMdocCredential with format '$FORMAT' and docType '$docType'")
    }

    @Serializable
    @SerialName(FORMAT)
    data class CredentialIssuanceRequestTO(
        @SerialName("doctype") val docType: String,
        @SerialName("proof") override val proof: JsonObject?,
        @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject? = null,
        @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String? = null,
        @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
        @SerialName("claims") val claims: JsonObject?,
    ) : eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequestTO.SingleCredentialTO

    data class ClaimSet(
        val claims: Map<Namespace, Map<ClaimName, Claim>>,
    ) : eu.europa.ec.eudi.openid4vci.ClaimSet

    /**
     * Issuance request for a credential of mso_mdoc format
     */
    class CredentialIssuanceRequest private constructor(
        val doctype: String,
        override val proof: Proof? = null,
        override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
        val claimSet: ClaimSet?,
    ) : eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequest.SingleCredential {

        override val format: String = "mso_mdoc"

        companion object {
            operator fun invoke(
                proof: Proof? = null,
                credentialEncryptionJwk: JWK? = null,
                credentialResponseEncryptionAlg: JWEAlgorithm? = null,
                credentialResponseEncryptionMethod: EncryptionMethod? = null,
                doctype: String,
                claimSet: ClaimSet? = null,
            ): Result<CredentialIssuanceRequest> = runCatching {
                CredentialIssuanceRequest(
                    proof = proof,
                    requestedCredentialResponseEncryption =
                        eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequest.SingleCredential.requestedCredentialResponseEncryption(
                            credentialEncryptionJwk = credentialEncryptionJwk,
                            credentialResponseEncryptionAlg = credentialResponseEncryptionAlg,
                            credentialResponseEncryptionMethod = credentialResponseEncryptionMethod,
                        ),
                    doctype = doctype,
                    claimSet = claimSet,
                )
            }
        }
    }
}
