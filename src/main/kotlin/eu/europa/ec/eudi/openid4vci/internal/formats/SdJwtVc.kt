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

internal data object SdJwtVc :
    IssuanceRequestFactory<SdJwtVcCredential, GenericClaimSet, SdJwtVcIssuanceRequest> {

    const val FORMAT = "vc+sd-jwt"

    override fun createIssuanceRequest(
        supportedCredential: SdJwtVcCredential,
        claimSet: GenericClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<SdJwtVcIssuanceRequest> = runCatching {
        fun GenericClaimSet.validate() {
            if ((supportedCredential.credentialDefinition.claims.isNullOrEmpty()) && claims.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT-${supportedCredential.credentialDefinition.type}]",
                )
            }
            if (supportedCredential.credentialDefinition.claims != null &&
                !supportedCredential.credentialDefinition.claims.keys.containsAll(claims)
            ) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Claim names requested are not supported by issuer",
                )
            }
        }

        val validClaimSet = claimSet?.apply { validate() }

        SdJwtVcIssuanceRequest(
            type = supportedCredential.credentialDefinition.type,
            credentialEncryptionJwk = responseEncryptionSpec?.jwk,
            credentialResponseEncryptionAlg = responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod = responseEncryptionSpec?.encryptionMethod,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }
}

internal class SdJwtVcIssuanceRequest private constructor(
    override val proof: Proof? = null,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    val credentialDefinition: CredentialDefinition,
) : SingleCredential {

    override val format: String = SdJwtVc.FORMAT

    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        SdJwtVcFormatSerializationSupport.issuanceRequestToJson(this)

    data class CredentialDefinition(val type: String, val claims: GenericClaimSet?)

    companion object {
        operator fun invoke(
            type: String,
            proof: Proof? = null,
            credentialEncryptionJwk: JWK? = null,
            credentialResponseEncryptionAlg: JWEAlgorithm? = null,
            credentialResponseEncryptionMethod: EncryptionMethod? = null,
            claimSet: GenericClaimSet? = null,
        ): Result<SdJwtVcIssuanceRequest> = runCatching {
            SdJwtVcIssuanceRequest(
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

@Serializable
@SerialName(SdJwtVc.FORMAT)
internal data class SdJwtVcIssuanceRequestTO(
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject? = null,
    @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String? = null,
    @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
    @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO,
) : CredentialIssuanceRequestTO.SingleCredentialTO {

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("type") val type: String,
        @SerialName("claims") val claims: JsonObject? = null,
    )
}

@Serializable
@SerialName(SdJwtVc.FORMAT)
internal data class SdJwtVcCredentialTO(
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

    override fun toDomain(): CredentialSupported = SdJwtVcFormatSerializationSupport.credentialSupportedFromJson(this)
}

internal object SdJwtVcFormatSerializationSupport :
    FormatSerializationSupport<SdJwtVcCredentialTO, SdJwtVcCredential, SdJwtVcIssuanceRequest, SdJwtVcIssuanceRequestTO> {
    override fun credentialSupportedFromJson(csJson: SdJwtVcCredentialTO): SdJwtVcCredential {
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

    private fun SdJwtVcCredentialTO.CredentialDefinitionTO.toDomain(): SdJwtVcCredential.CredentialDefinition =
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

    override fun issuanceRequestToJson(request: SdJwtVcIssuanceRequest): SdJwtVcIssuanceRequestTO {
        return when (val it = request.requestedCredentialResponseEncryption) {
            is RequestedCredentialResponseEncryption.NotRequested -> SdJwtVcIssuanceRequestTO(
                proof = request.proof,
                credentialDefinition = SdJwtVcIssuanceRequestTO.CredentialDefinitionTO(
                    type = request.credentialDefinition.type,
                    claims = request.credentialDefinition.claims?.let {
                        buildJsonObject {
                            for (c in it.claims) {
                                put(c, JsonObject(emptyMap()))
                            }
                        }
                    },
                ),
            )

            is RequestedCredentialResponseEncryption.Requested -> SdJwtVcIssuanceRequestTO(
                proof = request.proof,
                credentialEncryptionJwk = Json.parseToJsonElement(
                    it.encryptionJwk.toPublicJWK().toString(),
                ).jsonObject,
                credentialResponseEncryptionAlg = it.responseEncryptionAlg.toString(),
                credentialResponseEncryptionMethod = it.responseEncryptionMethod.toString(),
                credentialDefinition = SdJwtVcIssuanceRequestTO.CredentialDefinitionTO(
                    type = request.credentialDefinition.type,
                    claims = request.credentialDefinition.claims?.let {
                        Json.encodeToJsonElement(it.claims).jsonObject
                    },
                ),
            )
        }
    }
}
