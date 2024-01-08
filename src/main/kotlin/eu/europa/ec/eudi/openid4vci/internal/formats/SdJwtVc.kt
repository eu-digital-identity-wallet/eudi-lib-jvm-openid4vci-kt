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
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.util.*

internal data object SdJwtVc : Format<SdJwtVc.Model.SdJwtVcCredential, SdJwtVc.Model.CredentialIssuanceRequest> {

    const val FORMAT = "vc+sd-jwt"

    override fun constructIssuanceRequest(
        supportedCredential: Model.SdJwtVcCredential,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<Model.CredentialIssuanceRequest> = runCatching {
        fun validateClaimSet(claimSet: Model.ClaimSet): Model.ClaimSet {
            if ((supportedCredential.credentialDefinition.claims.isNullOrEmpty()) && claimSet.claims.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT-${supportedCredential.credentialDefinition.type}]",
                )
            }
            if (supportedCredential.credentialDefinition.claims != null &&
                !supportedCredential.credentialDefinition.claims.keys.containsAll(claimSet.claims.keys)
            ) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Claim names requested are not supported by issuer",
                )
            }
            return claimSet
        }

        val validClaimSet = claimSet?.let {
            when (claimSet) {
                is Model.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        Model.CredentialIssuanceRequest(
            type = supportedCredential.credentialDefinition.type,
            credentialEncryptionJwk = responseEncryptionSpec?.jwk,
            credentialResponseEncryptionAlg = responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod = responseEncryptionSpec?.encryptionMethod,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    object Model {

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
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupportedTO {
            init {
                require(format == FORMAT) { "invalid format '$format'" }
            }

            @Serializable
            data class CredentialDefinitionTO(
                @SerialName("type") val type: String,
                @SerialName("claims") val claims: Map<String, ClaimTO>? = null,
            )

            override fun toDomain(): CredentialSupported {
                val bindingMethods =
                    cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
                        ?: emptyList()
                val display = display?.map { it.toDomain() } ?: emptyList()
                val proofTypesSupported = proofTypesSupported.toProofTypes()
                val cryptographicSuitesSupported = cryptographicSuitesSupported ?: emptyList()

                return SdJwtVcCredential(
                    scope,
                    bindingMethods,
                    cryptographicSuitesSupported,
                    proofTypesSupported,
                    display,
                    credentialDefinition.toDomain(),
                )
            }
        }

        private fun CredentialSupportedTO.CredentialDefinitionTO.toDomain(): SdJwtVcCredential.CredentialDefinition =
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

        data class SdJwtVcCredential(
            override val scope: String? = null,
            override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
            override val cryptographicSuitesSupported: List<String> = emptyList(),
            override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
            override val display: List<Display> = emptyList(),
            val credentialDefinition: CredentialDefinition,
        ) : CredentialSupported {
            data class CredentialDefinition(
                val type: String,
                val claims: Map<ClaimName, Claim?>?,
            )
        }

        @Serializable
        @SerialName(FORMAT)
        data class CredentialIssuanceRequestTO(
            @SerialName("proof") override val proof: Proof? = null,
            @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject? = null,
            @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String? = null,
            @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
            @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO.SingleCredentialTO {

            @Serializable
            data class CredentialDefinitionTO(
                @SerialName("type") val type: String,
                @SerialName("claims") val claims: JsonObject? = null,
            )
        }

        data class ClaimSet(
            val claims: Map<ClaimName, Claim>,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.ClaimSet

        class CredentialIssuanceRequest private constructor(
            override val proof: Proof? = null,
            override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
            val credentialDefinition: CredentialDefinition,
        ) : SingleCredential {

            override val format: String = FORMAT

            override fun toTransferObject(): eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO.SingleCredentialTO {
                return when (val it = this.requestedCredentialResponseEncryption) {
                    is RequestedCredentialResponseEncryption.NotRequested -> CredentialIssuanceRequestTO(
                        proof = this.proof,
                        credentialDefinition = CredentialIssuanceRequestTO.CredentialDefinitionTO(
                            type = this.credentialDefinition.type,
                            claims = this.credentialDefinition.claims?.let {
                                Json.encodeToJsonElement(it.claims).jsonObject
                            },
                        ),
                    )

                    is RequestedCredentialResponseEncryption.Requested -> CredentialIssuanceRequestTO(
                        proof = this.proof,
                        credentialEncryptionJwk = Json.parseToJsonElement(
                            it.encryptionJwk.toPublicJWK().toString(),
                        ).jsonObject,
                        credentialResponseEncryptionAlg = it.responseEncryptionAlg.toString(),
                        credentialResponseEncryptionMethod = it.responseEncryptionMethod.toString(),
                        credentialDefinition = CredentialIssuanceRequestTO.CredentialDefinitionTO(
                            type = this.credentialDefinition.type,
                            claims = this.credentialDefinition.claims?.let {
                                Json.encodeToJsonElement(it.claims).jsonObject
                            },
                        ),
                    )
                }
            }

            data class CredentialDefinition(
                val type: String,
                val claims: ClaimSet?,
            )

            companion object {
                operator fun invoke(
                    type: String,
                    proof: Proof? = null,
                    credentialEncryptionJwk: JWK? = null,
                    credentialResponseEncryptionAlg: JWEAlgorithm? = null,
                    credentialResponseEncryptionMethod: EncryptionMethod? = null,
                    claimSet: ClaimSet? = null,
                ): Result<CredentialIssuanceRequest> = runCatching {
                    CredentialIssuanceRequest(
                        proof = proof,
                        requestedCredentialResponseEncryption =
                            SingleCredential.requestedCredentialResponseEncryption(
                                credentialEncryptionJwk = credentialEncryptionJwk,
                                credentialResponseEncryptionAlg = credentialResponseEncryptionAlg,
                                credentialResponseEncryptionMethod = credentialResponseEncryptionMethod,
                            ),
                        credentialDefinition = CredentialDefinition(
                            type = type,
                            claims = claimSet,
                        ),
                    )
                }
            }
        }
    }
}
