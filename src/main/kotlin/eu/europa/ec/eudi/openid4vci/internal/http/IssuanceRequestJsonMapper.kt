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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.*
import eu.europa.ec.eudi.openid4vci.internal.*
import eu.europa.ec.eudi.openid4vci.internal.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.CredentialType
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.ensure
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

//
// Batch request / response
//
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
internal data class BatchCredentialResponseSuccessTO(
    @SerialName("credential_responses") val credentialResponses: List<IssuanceResponseTO>,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
) {

    fun toDomain(): CredentialIssuanceResponse {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        return CredentialIssuanceResponse(
            cNonce = cNonce,
            credentials = credentialResponses.map {
                issuedCredentialOf(
                    it.transactionId,
                    it.notificationId,
                    it.credential,
                )
            },
        )
    }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): BatchCredentialResponseSuccessTO = with(jwtClaimsSet) {
            val jsonArray = JSONObjectUtils.getJSONObjectArray(claims, "credential_responses")
            ensure(jsonArray != null) {
                InvalidBatchIssuanceResponse("missing credential_responses in response")
            }
            BatchCredentialResponseSuccessTO(
                credentialResponses = jsonArray.map { attr ->
                    IssuanceResponseTO(
                        credential = JSONObjectUtils.getString(attr, "credential"),
                        transactionId = JSONObjectUtils.getString(attr, "transaction_id"),
                        notificationId = JSONObjectUtils.getString(attr, "notification_id"),
                    )
                },
                cNonce = getStringClaim("c_nonce"),
                cNonceExpiresInSeconds = getLongClaim("c_nonce_expires_in"),
            )
        }
    }
}

@Serializable
internal data class IssuanceResponseTO(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
)

//
// Credential request / response
//
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
internal data class CredentialResponseSuccessTO(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
) {
    fun toDomain(): CredentialIssuanceResponse {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        val issuedCredential = issuedCredentialOf(transactionId, notificationId, credential)
        return CredentialIssuanceResponse(
            cNonce = cNonce,
            credentials = listOf(issuedCredential),
        )
    }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): CredentialResponseSuccessTO =
            CredentialResponseSuccessTO(
                credential = jwtClaimsSet.getStringClaim("credential"),
                transactionId = jwtClaimsSet.getStringClaim("transaction_id"),
                notificationId = jwtClaimsSet.getStringClaim("notification_id"),
                cNonce = jwtClaimsSet.getStringClaim("c_nonce"),
                cNonceExpiresInSeconds = jwtClaimsSet.getLongClaim("c_nonce_expires_in"),
            )
    }
}

private fun issuedCredentialOf(
    transactionId: String?,
    notificationId: String?,
    credential: String?,
): IssuedCredential {
    ensure(!(transactionId == null && credential == null)) {
        val error =
            "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters"
        ResponseUnparsable(error)
    }
    return when {
        transactionId != null -> IssuedCredential.Deferred(TransactionId(transactionId))
        credential != null -> {
            val notificationIdentifier = notificationId?.let { NotificationId(notificationId) }
            IssuedCredential.Issued(credential, notificationIdentifier)
        }

        else -> error("Cannot happen")
    }
}

//
// Deferred request / response
//

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

@Serializable
internal data class DeferredIssuanceSuccessResponseTO(
    @SerialName("credential") val credential: String,
) {
    fun toDomain(): DeferredCredentialQueryOutcome.Issued {
        return DeferredCredentialQueryOutcome.Issued(IssuedCredential.Issued(credential))
    }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): DeferredIssuanceSuccessResponseTO {
            return DeferredIssuanceSuccessResponseTO(jwtClaimsSet.getStringClaim("credential"))
        }
    }
}

//
// Notification
//

@Serializable
internal class NotificationTO(
    @SerialName("notification_id") val id: String,
    @SerialName("event") val event: NotificationEventTO,
    @SerialName("event_description") val description: String? = null,
) {
    companion object {
        fun from(credentialIssuanceEvent: CredentialIssuanceEvent): NotificationTO =
            when (credentialIssuanceEvent) {
                is CredentialIssuanceEvent.Accepted -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_ACCEPTED,
                    description = credentialIssuanceEvent.description,
                )

                is CredentialIssuanceEvent.Deleted -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_DELETED,
                    description = credentialIssuanceEvent.description,
                )

                is CredentialIssuanceEvent.Failed -> NotificationTO(
                    id = credentialIssuanceEvent.id.value,
                    event = NotificationEventTO.CREDENTIAL_FAILURE,
                    description = credentialIssuanceEvent.description,
                )
            }
    }
}

@Serializable
internal enum class NotificationEventTO {
    @SerialName("credential_accepted")
    CREDENTIAL_ACCEPTED,

    @SerialName("credential_failure")
    CREDENTIAL_FAILURE,

    @SerialName("credential_deleted")
    CREDENTIAL_DELETED,
}

//
// Error response
//

@Serializable
internal data class GenericErrorResponseTO(
    @SerialName("error") val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
    @SerialName("interval") val interval: Long? = null,
) {

    fun toIssuanceError(): CredentialIssuanceError = when (error) {
        "invalid_proof" ->
            cNonce
                ?.let { InvalidProof(cNonce, cNonceExpiresInSeconds, errorDescription) }
                ?: ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")

        "issuance_pending" ->
            interval
                ?.let { DeferredCredentialIssuancePending(interval) }
                ?: DeferredCredentialIssuancePending()

        "invalid_token" -> InvalidToken
        "invalid_transaction_id " -> InvalidTransactionId
        "unsupported_credential_type " -> UnsupportedCredentialType
        "unsupported_credential_format " -> UnsupportedCredentialFormat
        "invalid_encryption_parameters " -> InvalidEncryptionParameters
        else -> IssuanceRequestFailed(error, errorDescription)
    }

    fun toDeferredCredentialQueryOutcome(): DeferredCredentialQueryOutcome =
        when (error) {
            "issuance_pending" -> DeferredCredentialQueryOutcome.IssuancePending(interval)
            else -> DeferredCredentialQueryOutcome.Errored(error, errorDescription)
        }
}
