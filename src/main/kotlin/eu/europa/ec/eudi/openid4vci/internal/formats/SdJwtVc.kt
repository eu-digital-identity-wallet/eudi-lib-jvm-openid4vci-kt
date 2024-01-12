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
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import eu.europa.ec.eudi.openid4vci.internal.formats.SdJwtVcIssuanceRequest.CredentialDefinition
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.util.*

internal data object SdJwtVc :
    Format<SdJwtVcCredential, GenericClaimSet, SdJwtVcIssuanceRequest, SdJwtVcIssuanceRequestTO> {

    const val FORMAT = "vc+sd-jwt"

    override val serializationSupport:
        FormatSerializationSupport<SdJwtVcIssuanceRequest, SdJwtVcIssuanceRequestTO>
        get() = SdJwtVcFormatSerializationSupport

    override fun createIssuanceRequest(
        supportedCredential: SdJwtVcCredential,
        claimSet: GenericClaimSet?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
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
            proof = proof,
            requestedCredentialResponseEncryption = requestedCredentialResponseEncryption,
            credentialDefinition = CredentialDefinition(
                type = supportedCredential.credentialDefinition.type,
                claims = validClaimSet,
            ),
        )
    }
}

internal class SdJwtVcIssuanceRequest(
    override val proof: Proof? = null,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    val credentialDefinition: CredentialDefinition,
) : SingleCredential {

    override val format: String = SdJwtVc.FORMAT

    @Deprecated("Don't use it")
    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        SdJwtVcFormatSerializationSupport.issuanceRequestToJson(this)

    data class CredentialDefinition(val type: String, val claims: GenericClaimSet?)
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

private object SdJwtVcFormatSerializationSupport :
    FormatSerializationSupport<SdJwtVcIssuanceRequest, SdJwtVcIssuanceRequestTO> {

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
