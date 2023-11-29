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
import eu.europa.ec.eudi.openid4vci.internal.ClaimSetSerializer
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import kotlinx.serialization.*
import kotlinx.serialization.json.*
import java.util.*

internal data object MsoMdoc : Format<MsoMdoc.Model.CredentialSupported, MsoMdoc.Model.CredentialIssuanceRequest> {

    const val FORMAT = "mso_mdoc"

    override fun constructIssuanceRequest(
        supportedCredential: Model.CredentialSupported,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<Model.CredentialIssuanceRequest> = runCatching {
        fun validateClaimSet(claims: Model.ClaimSet): Model.ClaimSet {
            if (claims.isEmpty() && claims.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${supportedCredential.docType}]",
                )
            }
            claims.forEach { (nameSpace, attributes) ->
                supportedCredential.claims[nameSpace]?.let { supportedClaim ->
                    if (!supportedClaim.keys.containsAll(attributes.keys)) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest(
                            "Claim names requested are not supported by issuer",
                        )
                    }
                }
                    ?: throw CredentialIssuanceError.InvalidIssuanceRequest("Namespace $nameSpace not supported by issuer")
            }
            return claims
        }

        val validClaimSet = claimSet?.let {
            when (claimSet) {
                is Model.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        Model.CredentialIssuanceRequest(
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

            override fun toDomain(): CredentialSupported {
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
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported

        @Serializable
        data class CredentialMetadataTO(
            @SerialName("format") @Required val format: String,
            @SerialName("doctype") @Required val docType: String,
        )

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

        @Serializable(with = ClaimSetSerializer::class)
        class ClaimSet(
            claims: Map<Namespace, Map<ClaimName, Claim>>,
        ) : eu.europa.ec.eudi.openid4vci.internal.formats.ClaimSet, Map<Namespace, Map<ClaimName, Claim>> by claims

        /**
         * Issuance request for a credential of mso_mdoc format
         */
        class CredentialIssuanceRequest private constructor(
            val doctype: String,
            override val proof: Proof? = null,
            override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
            val claimSet: ClaimSet?,
        ) : SingleCredential {

            override val format: String = "mso_mdoc"
            override fun toTransferObject(): eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO.SingleCredentialTO {
                return when (val it = requestedCredentialResponseEncryption) {
                    is RequestedCredentialResponseEncryption.NotRequested -> {
                        CredentialIssuanceRequestTO(
                            docType = this.doctype,
                            proof = this.proof,
                            claims = this.claimSet?.let {
                                Json.encodeToJsonElement(it).jsonObject
                            },
                        )
                    }

                    is RequestedCredentialResponseEncryption.Requested -> {
                        CredentialIssuanceRequestTO(
                            docType = this.doctype,
                            proof = this.proof,
                            credentialEncryptionJwk = Json.parseToJsonElement(
                                it.encryptionJwk.toPublicJWK().toString(),
                            ).jsonObject,
                            credentialResponseEncryptionAlg = it.responseEncryptionAlg.toString(),
                            credentialResponseEncryptionMethod = it.responseEncryptionMethod.toString(),
                            claims = this.claimSet?.let {
                                Json.encodeToJsonElement(it).jsonObject
                            },
                        )
                    }
                }
            }

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
    }
}
