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
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

internal object IssuanceRequestJsonMapper {
    fun asJson(request: CredentialIssuanceRequest.SingleRequest): CredentialRequestTO =
        CredentialRequestTO.from(request)

    fun asJson(request: CredentialIssuanceRequest.BatchRequest): BatchCredentialRequestTO =
        BatchCredentialRequestTO.from(request)

    fun asJson(
        deferredCredential: IssuedCredential.Deferred,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): DeferredRequestTO = DeferredRequestTO.from(deferredCredential, responseEncryptionSpec)
}

@Serializable
internal data class BatchCredentialRequestTO(
    @SerialName("credential_requests") val credentialRequests: List<CredentialRequestTO>,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionSpecTO? = null,
) {
    companion object {
        fun from(batchRequest: CredentialIssuanceRequest.BatchRequest): BatchCredentialRequestTO {
            val credentialRequests = batchRequest.credentialRequests.map { CredentialRequestTO.from(it) }
            val credentialResponseEncryption = batchRequest.encryption?.run {
                CredentialResponseEncryptionSpecTO.from(this)
            }
            return BatchCredentialRequestTO(credentialRequests, credentialResponseEncryption)
        }
    }
}

@Serializable
internal data class CredentialResponseEncryptionSpecTO(
    @SerialName("jwk") val jwk: JsonObject,
    @SerialName("alg") val encryptionAlgorithm: String,
    @SerialName("enc") val encryptionMethod: String,
) {
    companion object {

        fun from(responseEncryption: IssuanceResponseEncryptionSpec): CredentialResponseEncryptionSpecTO {
            val credentialEncryptionJwk =
                Json.parseToJsonElement(responseEncryption.jwk.toPublicJWK().toString()).jsonObject
            val credentialResponseEncryptionAlg = responseEncryption.algorithm.toString()
            val credentialResponseEncryptionMethod = responseEncryption.encryptionMethod.toString()
            return CredentialResponseEncryptionSpecTO(
                credentialEncryptionJwk,
                credentialResponseEncryptionAlg,
                credentialResponseEncryptionMethod,
            )
        }
    }
}

@Serializable
internal data class CredentialDefinitionTO(
    @SerialName("type") val type: List<String>,
    @SerialName("credentialSubject") val credentialSubject: JsonObject? = null,
)

@Serializable
internal data class CredentialRequestTO(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("format") val format: String? = null,
    @SerialName("doctype") val docType: String? = null,
    @SerialName("vct") val vct: String? = null,
    @SerialName("proof") val proof: Proof? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("claims") val claims: JsonObject? = null,
    @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO? = null,
) {
    init {
        require(format != null || credentialIdentifier != null) { "Either format or credentialIdentifier must be set" }
    }

    companion object {

        private fun credentialResponseEncryption(request: CredentialIssuanceRequest) =
            request.encryption?.run {
                CredentialResponseEncryptionSpecTO.from(this)
            }

        fun from(request: CredentialIssuanceRequest.FormatBased, credential: CredentialType.MsoMdocDocType) =
            CredentialRequestTO(
                format = FORMAT_MSO_MDOC,
                proof = request.proof,
                credentialResponseEncryption = credentialResponseEncryption(request),
                docType = credential.doctype,
                claims = credential.claimSet?.let {
                    Json.encodeToJsonElement(it).jsonObject
                },
            )

        fun from(request: CredentialIssuanceRequest.FormatBased, credential: CredentialType.SdJwtVcType) =
            CredentialRequestTO(
                format = FORMAT_SD_JWT_VC,
                proof = request.proof,
                credentialResponseEncryption = credentialResponseEncryption(request),
                vct = credential.type,
                claims = credential.claims?.let {
                    buildJsonObject {
                        it.claims.forEach { claimName ->
                            put(claimName, JsonObject(emptyMap()))
                        }
                    }
                },
            )

        fun from(request: CredentialIssuanceRequest.FormatBased, credential: CredentialType.W3CSignedJwtType) =
            CredentialRequestTO(
                format = FORMAT_W3C_SIGNED_JWT,
                proof = request.proof,
                credentialResponseEncryption = credentialResponseEncryption(request),
                credentialDefinition = CredentialDefinitionTO(
                    type = credential.type,
                    credentialSubject = credential.claims?.let {
                        buildJsonObject {
                            it.claims.forEach { claimName ->
                                put(claimName, JsonObject(emptyMap()))
                            }
                        }
                    },
                ),
            )

        fun from(request: CredentialIssuanceRequest.IdentifierBased) =
            CredentialRequestTO(
                credentialIdentifier = request.credentialId.value,
                proof = request.proof,
                credentialResponseEncryption = credentialResponseEncryption(request),
            )

        fun from(request: CredentialIssuanceRequest.SingleRequest): CredentialRequestTO {
            return when (request) {
                is CredentialIssuanceRequest.FormatBased -> when (val credential = request.credential) {
                    is CredentialType.MsoMdocDocType -> from(request, credential)
                    is CredentialType.SdJwtVcType -> from(request, credential)
                    is CredentialType.W3CSignedJwtType -> from(request, credential)
                }

                is CredentialIssuanceRequest.IdentifierBased -> from(request)
            }
        }
    }
}

@Serializable
internal data class DeferredRequestTO(
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("credential_response_encryption") val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
) {
    companion object {
        fun from(
            deferredCredential: IssuedCredential.Deferred,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): DeferredRequestTO {
            val transactionId = deferredCredential.transactionId.value
            val credentialResponseEncryptionSpecTO = responseEncryptionSpec?.run {
                CredentialResponseEncryptionSpecTO.from(this)
            }
            return DeferredRequestTO(transactionId, credentialResponseEncryptionSpecTO)
        }
    }
}
