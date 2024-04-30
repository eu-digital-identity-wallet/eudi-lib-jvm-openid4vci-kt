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
    fun asJson(request: CredentialIssuanceRequest.SingleRequest): SingleCredentialTO = transferObjectOfSingle(request)
    fun asJson(request: CredentialIssuanceRequest.BatchRequest): BatchCredentialsTO = toTransferObject(request)
}

private fun toTransferObject(request: CredentialIssuanceRequest.BatchRequest): BatchCredentialsTO =
    request.credentialRequests
        .map { transferObjectOfSingle(it) }
        .let { BatchCredentialsTO(it) }

private fun transferObjectOfSingle(
    request: CredentialIssuanceRequest.SingleRequest,
): SingleCredentialTO {
    val credentialResponseEncryptionSpecTO = request.encryption?.run { transferObject() }

    return when (request) {
        is CredentialIssuanceRequest.FormatBased ->
            when (val credential = request.credential) {
                is CredentialType.MsoMdocDocType -> SingleCredentialTO(
                    format = FORMAT_MSO_MDOC,
                    proof = request.proof,
                    credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
                    docType = credential.doctype,
                    claims = credential.claimSet?.let {
                        Json.encodeToJsonElement(it).jsonObject
                    },
                )

                is CredentialType.SdJwtVcType -> SingleCredentialTO(
                    format = FORMAT_SD_JWT_VC,
                    proof = request.proof,
                    credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
                    vct = credential.type,
                    claims = credential.claims?.let {
                        buildJsonObject {
                            it.claims.forEach { claimName ->
                                put(claimName, JsonObject(emptyMap()))
                            }
                        }
                    },
                )

                is CredentialType.W3CSignedJwtType -> SingleCredentialTO(
                    format = FORMAT_W3C_SIGNED_JWT,
                    proof = request.proof,
                    credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
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
            }

        is CredentialIssuanceRequest.IdentifierBased -> SingleCredentialTO(
            credentialIdentifier = request.credentialId.value,
            proof = request.proof,
            credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
        )
    }
}

internal fun IssuanceResponseEncryptionSpec.transferObject(): CredentialResponseEncryptionSpecTO {
    val credentialEncryptionJwk = Json.parseToJsonElement(jwk.toPublicJWK().toString()).jsonObject
    val credentialResponseEncryptionAlg = algorithm.toString()
    val credentialResponseEncryptionMethod = encryptionMethod.toString()
    return CredentialResponseEncryptionSpecTO(
        credentialEncryptionJwk,
        credentialResponseEncryptionAlg,
        credentialResponseEncryptionMethod,
    )
}

@Serializable
internal data class BatchCredentialsTO(
    @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
)

@Serializable
internal data class CredentialResponseEncryptionSpecTO(
    @SerialName("jwk") val jwk: JsonObject,
    @SerialName("alg") val encryptionAlgorithm: String,
    @SerialName("enc") val encryptionMethod: String,
)

@Serializable
internal data class CredentialDefinitionTO(
    @SerialName("type") val type: List<String>,
    @SerialName("credentialSubject") val credentialSubject: JsonObject? = null,
)

@Serializable
internal data class SingleCredentialTO(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("format") val format: String? = null,
    @SerialName("doctype") val docType: String? = null,
    @SerialName("vct") val vct: String? = null,
    @SerialName("proof") val proof: Proof? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("claims") val claims: JsonObject? = null,
    @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO? = null,
) {
    init {
        require(format != null || credentialIdentifier != null) { "Either format or credentialIdentifier must be set" }
    }
}

@Serializable
internal data class DeferredIssuanceRequestTO(
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("credential_response_encryption") val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
)

internal object DeferredRequestJsonMapper {

    fun asJson(
        deferredCredential: IssuedCredential.Deferred,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): DeferredIssuanceRequestTO {
        val transactionId = deferredCredential.transactionId.value
        val credentialResponseEncryptionSpecTO = responseEncryptionSpec?.run { transferObject() }
        return DeferredIssuanceRequestTO(transactionId, credentialResponseEncryptionSpecTO)
    }
}
