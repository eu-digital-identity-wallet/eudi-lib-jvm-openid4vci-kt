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

import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidIssuanceRequest
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.MsoMdocClaimSet
import eu.europa.ec.eudi.openid4vci.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

fun CredentialIssuerMetadata.findMsoMdoc(docType: String): MsoMdocCredential? =
    findByFormat<MsoMdocCredential> { it.docType == docType }.values.firstOrNull()

internal data object MsoMdoc :
    Format<MsoMdocCredential, MsoMdocClaimSet, MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO> {

    const val FORMAT = "mso_mdoc"

    override val serializationSupport:
        FormatSerializationSupport<MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO>
        get() = MsoMdocFormatSerializationSupport

    override fun createIssuanceRequest(
        supportedCredential: MsoMdocCredential,
        claimSet: MsoMdocClaimSet?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    ): Result<MsoMdocIssuanceRequest> = runCatching {
        fun MsoMdocClaimSet.validate() {
            if (supportedCredential.claims.isEmpty() && isNotEmpty()) {
                throw InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${supportedCredential.docType}]",
                )
            }
            forEach { (nameSpace, claimName) ->
                supportedCredential.claims[nameSpace]?.let { supportedClaimNames ->
                    if (claimName !in supportedClaimNames) {
                        throw InvalidIssuanceRequest("Requested claim name $claimName is not supported by issuer")
                    }
                } ?: throw InvalidIssuanceRequest("Namespace $nameSpace not supported by issuer")
            }
        }

        val validClaimSet = claimSet?.apply { validate() }

        MsoMdocIssuanceRequest(
            proof = proof,
            requestedCredentialResponseEncryption = requestedCredentialResponseEncryption,
            doctype = supportedCredential.docType,
            claimSet = validClaimSet,
        )
    }
}

@Serializable
@SerialName(MsoMdoc.FORMAT)
internal data class MsoMdocIssuanceRequestTO(
    @SerialName("doctype") val docType: String,
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject? = null,
    @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String? = null,
    @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
    @SerialName("claims") val claims: JsonObject?,
) : CredentialIssuanceRequestTO.SingleCredentialTO

/**
 * Issuance request for a credential of mso_mdoc format
 */
internal class MsoMdocIssuanceRequest(
    override val proof: Proof? = null,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    val doctype: String,
    val claimSet: MsoMdocClaimSet?,
) : SingleCredential {

    override val format: String = "mso_mdoc"
    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        MsoMdocFormatSerializationSupport.issuanceRequestToJson(this)
}

private object MsoMdocFormatSerializationSupport :
    FormatSerializationSupport<MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO> {

    override fun issuanceRequestToJson(request: MsoMdocIssuanceRequest): MsoMdocIssuanceRequestTO {
        return when (val it = request.requestedCredentialResponseEncryption) {
            is RequestedCredentialResponseEncryption.NotRequested -> {
                MsoMdocIssuanceRequestTO(
                    docType = request.doctype,
                    proof = request.proof,
                    claims = request.claimSet?.let {
                        Json.encodeToJsonElement(it).jsonObject
                    },
                )
            }

            is RequestedCredentialResponseEncryption.Requested -> {
                MsoMdocIssuanceRequestTO(
                    docType = request.doctype,
                    proof = request.proof,
                    credentialEncryptionJwk = Json.parseToJsonElement(
                        it.encryptionJwk.toPublicJWK().toString(),
                    ).jsonObject,
                    credentialResponseEncryptionAlg = it.responseEncryptionAlg.toString(),
                    credentialResponseEncryptionMethod = it.responseEncryptionMethod.toString(),
                    claims = request.claimSet?.let {
                        Json.encodeToJsonElement(it).jsonObject
                    },
                )
            }
        }
    }
}
