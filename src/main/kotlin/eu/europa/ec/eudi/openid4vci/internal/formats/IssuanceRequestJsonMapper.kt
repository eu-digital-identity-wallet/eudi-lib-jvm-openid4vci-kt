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

import eu.europa.ec.eudi.openid4vci.FORMAT_MSO_MDOC
import eu.europa.ec.eudi.openid4vci.FORMAT_SD_JWT_VC
import eu.europa.ec.eudi.openid4vci.FORMAT_W3C_SIGNED_JWT
import eu.europa.ec.eudi.openid4vci.IssuanceResponseEncryptionSpec
import eu.europa.ec.eudi.openid4vci.internal.Proof
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

internal object IssuanceRequestJsonMapper {
    fun asJson(request: CredentialIssuanceRequest): CredentialIssuanceRequestTO = toTransferObject(request)
}

private fun toTransferObject(request: CredentialIssuanceRequest): CredentialIssuanceRequestTO = when (request) {
    is CredentialIssuanceRequest.BatchRequest ->
        request.credentialRequests
            .map { transferObjectOfSingle(it) }
            .let { CredentialIssuanceRequestTO.BatchCredentialsTO(it) }

    is CredentialIssuanceRequest.SingleRequest -> transferObjectOfSingle(request)
}

private fun transferObjectOfSingle(
    request: CredentialIssuanceRequest.SingleRequest,
): CredentialIssuanceRequestTO.SingleCredentialTO {
    val credentialResponseEncryptionSpecTO = request.encryption?.run { transferObject() }

    return when (request) {
        is CredentialIssuanceRequest.FormatBased ->
            when (val credential = request.credential) {
                is CredentialType.MsoMdocDocType -> MsoMdocIssuanceRequestTO(
                    proof = request.proof,
                    credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
                    docType = credential.doctype,
                    claims = credential.claimSet?.let {
                        Json.encodeToJsonElement(it).jsonObject
                    },
                )

                is CredentialType.SdJwtVcType -> SdJwtVcIssuanceRequestTO(
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

                is CredentialType.W3CSignedJwtType -> W3CSignedJwtVcIssuanceRequestTO(
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

        is CredentialIssuanceRequest.IdentifierBased -> IdentifierBasedIssuanceRequestTO(
            proof = request.proof,
            credentialResponseEncryptionSpec = credentialResponseEncryptionSpecTO,
            configurationId = request.credentialId.value,
        )
    }
}

private fun IssuanceResponseEncryptionSpec.transferObject(): CredentialResponseEncryptionSpecTO {
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
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("_type_")
internal sealed interface CredentialIssuanceRequestTO {

    @Serializable
    @SerialName("batch-credential-request")
    data class BatchCredentialsTO(
        @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
    ) : CredentialIssuanceRequestTO

    @Serializable
    sealed interface SingleCredentialTO : CredentialIssuanceRequestTO {
        val proof: Proof?
        val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO?
    }
}

@Serializable
internal sealed interface FormatBasedIssuanceRequestTO : CredentialIssuanceRequestTO.SingleCredentialTO

@Serializable
@SerialName("identifier-based-request")
internal data class IdentifierBasedIssuanceRequestTO(
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_response_encryption") override val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("credential_identifier") val configurationId: String,
) : CredentialIssuanceRequestTO.SingleCredentialTO

@Serializable
internal data class CredentialResponseEncryptionSpecTO(
    @SerialName("jwk") val jwk: JsonObject,
    @SerialName("alg") val encryptionAlgorithm: String,
    @SerialName("enc") val encryptionMethod: String,
)

@Serializable
@OptIn(ExperimentalSerializationApi::class)
@SerialName("MsoMdocIssuanceRequestTO")
internal data class MsoMdocIssuanceRequestTO(
    @EncodeDefault @SerialName("format") private val format: String = FORMAT_MSO_MDOC,
    @SerialName("doctype") val docType: String,
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_response_encryption") override val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("claims") val claims: JsonObject?,
) : FormatBasedIssuanceRequestTO

@Serializable
@OptIn(ExperimentalSerializationApi::class)
@SerialName("SdJwtVcIssuanceRequestTO")
internal data class SdJwtVcIssuanceRequestTO(
    @EncodeDefault @SerialName("format") private val format: String = FORMAT_SD_JWT_VC,
    @SerialName("vct") val vct: String,
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_response_encryption") override val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
    @SerialName("claims") val claims: JsonObject? = null,
) : FormatBasedIssuanceRequestTO

@Serializable
@OptIn(ExperimentalSerializationApi::class)
@SerialName("W3CSignedJwtVcIssuanceRequestTO")
internal data class W3CSignedJwtVcIssuanceRequestTO(
    @EncodeDefault @SerialName("format") private val format: String = FORMAT_W3C_SIGNED_JWT,
    @SerialName("credential_definition") val credentialDefinition: CredentialDefinitionTO,
    @SerialName("proof") override val proof: Proof? = null,
    @SerialName("credential_response_encryption") override val credentialResponseEncryptionSpec: CredentialResponseEncryptionSpecTO? = null,
) : FormatBasedIssuanceRequestTO

@Serializable
internal data class CredentialDefinitionTO(
    @SerialName("type") val type: List<String>,
    @SerialName("credentialSubject") val credentialSubject: JsonObject? = null,
)
