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
    IssuanceRequestFactory<MsoMdocCredential, MsoMdocClaimSet, MsoMdocIssuanceRequest> {

    const val FORMAT = "mso_mdoc"

    override fun createIssuanceRequest(
        supportedCredential: MsoMdocCredential,
        claimSet: MsoMdocClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
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
            doctype = supportedCredential.docType,
            credentialEncryptionJwk = responseEncryptionSpec?.jwk,
            credentialResponseEncryptionAlg = responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod = responseEncryptionSpec?.encryptionMethod,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    object Model {
        /**
         * The data of a Verifiable Credentials issued as an ISO mDL.
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
            @SerialName("doctype") @Required val docType: String,
            @SerialName("claims") val claims: Map<String, Map<String, ClaimTO>>? = null,
            @SerialName("order") val order: List<String>? = null,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupportedTO {
            init {
                require(format == FORMAT) { "invalid format '$format'" }
            }

            override fun toDomain(): MsoMdocCredential {
                val bindingMethods = cryptographicBindingMethodsSupported
                    ?.toCryptographicBindingMethods()
                    ?: emptyList()
                val display = display?.map { it.toDomain() } ?: emptyList()
                val proofTypesSupported = proofTypesSupported.toProofTypes()
                val cryptographicSuitesSupported = cryptographicSuitesSupported ?: emptyList()

                fun claims(): MsoMdocClaims =
                    claims?.mapValues { (_, claims) ->
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

        @Serializable
        @SerialName(FORMAT)
        data class CredentialIssuanceRequestTO(
            @SerialName("doctype") val docType: String,
            @SerialName("proof") override val proof: Proof? = null,
            @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject? = null,
            @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String? = null,
            @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String? = null,
            @SerialName("claims") val claims: JsonObject?,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO.SingleCredentialTO

        fun transferObjectOf(
            request: MsoMdocIssuanceRequest,
        ): eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO.SingleCredentialTO {
            return when (val it = request.requestedCredentialResponseEncryption) {
                is RequestedCredentialResponseEncryption.NotRequested -> {
                    CredentialIssuanceRequestTO(
                        docType = request.doctype,
                        proof = request.proof,
                        claims = request.claimSet?.let {
                            Json.encodeToJsonElement(it).jsonObject
                        },
                    )
                }

                is RequestedCredentialResponseEncryption.Requested -> {
                    CredentialIssuanceRequestTO(
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
}

/**
 * Issuance request for a credential of mso_mdoc format
 */
internal class MsoMdocIssuanceRequest private constructor(
    val doctype: String,
    override val proof: Proof? = null,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    val claimSet: MsoMdocClaimSet?,
) : SingleCredential {

    override val format: String = "mso_mdoc"
    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        MsoMdoc.Model.transferObjectOf(this)

    companion object {
        operator fun invoke(
            proof: Proof? = null,
            credentialEncryptionJwk: JWK? = null,
            credentialResponseEncryptionAlg: JWEAlgorithm? = null,
            credentialResponseEncryptionMethod: EncryptionMethod? = null,
            doctype: String,
            claimSet: MsoMdocClaimSet? = null,
        ): Result<MsoMdocIssuanceRequest> = runCatching {
            MsoMdocIssuanceRequest(
                proof = proof,
                requestedCredentialResponseEncryption =
                    SingleCredential.requestedCredentialResponseEncryption(
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
