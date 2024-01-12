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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import java.util.*

fun CredentialIssuerMetadata.findMsoMdoc(docType: String): MsoMdocCredential? =
    findByFormat<MsoMdocCredential> { it.docType == docType }.values.firstOrNull()

internal data object MsoMdoc :
    Format<MsdMdocCredentialTO, MsoMdocCredential, MsoMdocClaimSet, MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO> {

    const val FORMAT = "mso_mdoc"

    override val serializationSupport:
        FormatSerializationSupport<MsdMdocCredentialTO, MsoMdocCredential, MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO>
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

/**
 * The data of a Verifiable Credentials issued as an ISO mDL.
 */
@Serializable
@SerialName(MsoMdoc.FORMAT)
internal data class MsdMdocCredentialTO(
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
) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupportedTO {
    init {
        require(format == MsoMdoc.FORMAT) { "invalid format '$format'" }
    }

    override fun toDomain(): MsoMdocCredential =
        MsoMdocFormatSerializationSupport.credentialSupportedFromJson(this)
}

private object MsoMdocFormatSerializationSupport :
    FormatSerializationSupport<MsdMdocCredentialTO, MsoMdocCredential, MsoMdocIssuanceRequest, MsoMdocIssuanceRequestTO> {
    override fun credentialSupportedFromJson(csJson: MsdMdocCredentialTO): MsoMdocCredential {
        val bindingMethods = csJson.cryptographicBindingMethodsSupported
            ?.toCryptographicBindingMethods()
            ?: emptyList()
        val display = csJson.display?.map { it.toDomain() } ?: emptyList()
        val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

        fun claims(): MsoMdocClaims =
            csJson.claims?.mapValues { (_, claims) ->
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
