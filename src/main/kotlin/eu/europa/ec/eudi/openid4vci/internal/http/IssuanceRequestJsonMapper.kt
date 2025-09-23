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
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.time.DurationUnit
import kotlin.time.toDuration

//
// Credential request / response
//
@Serializable
internal data class CredentialResponseEncryptionSpecTO(
    @SerialName("jwk") val jwk: JsonObject,
    @SerialName("enc") val encryptionMethod: String,
    @SerialName("zip") val compressionAlgorithm: String? = null,

) {
    companion object {

        fun from(responseEncryption: EncryptionSpec): CredentialResponseEncryptionSpecTO {
            val credentialEncryptionJwk =
                Json.parseToJsonElement(responseEncryption.recipientKey.toPublicJWK().toString()).jsonObject
            val credentialResponseEncryptionMethod = responseEncryption.encryptionMethod.toString()
            val encryptedPayloadCompressionAlgorithm = responseEncryption.compressionAlgorithm?.toString()
            return CredentialResponseEncryptionSpecTO(
                credentialEncryptionJwk,
                credentialResponseEncryptionMethod,
                encryptedPayloadCompressionAlgorithm,
            )
        }
    }
}

@Serializable
data class ProofsTO(
    @SerialName("jwt") val jwtProofs: List<String>? = null,
    @SerialName("di_vp") val diVpProofs: List<String>? = null,
    @SerialName("attestation") val attestationProofs: List<String>? = null,
) {

    init {
        require(!(jwtProofs.isNullOrEmpty() && diVpProofs.isNullOrEmpty() && attestationProofs.isNullOrEmpty()))
    }
}

@Serializable
internal data class CredentialRequestTO(
    @SerialName("credential_identifier") val credentialIdentifier: String? = null,
    @SerialName("credential_configuration_id") val credentialConfigurationId: String? = null,
    @SerialName("proofs") val proofs: ProofsTO? = null,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionSpecTO? = null,
) {
    init {
        require(credentialConfigurationId != null || credentialIdentifier != null) {
            "Either credentialConfigurationId or credentialIdentifier must be set"
        }
    }

    companion object {

        fun from(
            credentialIdentifier: CredentialIdentifier,
            proofs: List<Proof>,
            responseEncryption: EncryptionSpec?,
        ): CredentialRequestTO {
            val ps = proofs.proofsTO()
            return CredentialRequestTO(
                credentialIdentifier = credentialIdentifier.value,
                proofs = ps,
                credentialResponseEncryption = responseEncryption?.let(CredentialResponseEncryptionSpecTO::from),
            )
        }

        fun from(
            credentialConfigurationId: CredentialConfigurationIdentifier,
            proofs: List<Proof>,
            responseEncryption: EncryptionSpec?,
        ): CredentialRequestTO {
            val ps = proofs.proofsTO()
            return CredentialRequestTO(
                credentialConfigurationId = credentialConfigurationId.value,
                proofs = ps,
                credentialResponseEncryption = responseEncryption?.let(CredentialResponseEncryptionSpecTO::from),
            )
        }

        fun from(request: CredentialIssuanceRequest): CredentialRequestTO {
            val (ref, proofs, encryption) = request
            return when (ref) {
                is CredentialConfigurationReference.ByCredentialId ->
                    from(ref.credentialIdentifier, proofs, encryption.responseEncryptionSpec)

                is CredentialConfigurationReference.ByCredentialConfigurationId ->
                    from(ref.credentialConfigurationId, proofs, encryption.responseEncryptionSpec)
            }
        }

        fun toJwtClaimsSet(to: CredentialRequestTO): JWTClaimsSet =
            JWTClaimsSet.parse(JsonSupport.encodeToString(to))

        private fun List<Proof>?.proofsTO(): ProofsTO? =
            if (this.isNullOrEmpty()) null
            else ProofsTO(
                jwtProofs = filterIsInstance<Proof.Jwt>().map { it.jwt.serialize() }.takeIf { it.isNotEmpty() },
                diVpProofs = filterIsInstance<Proof.DiVp>().map { it.diVp }.takeIf { it.isNotEmpty() },
                attestationProofs = filterIsInstance<Proof.Attestation>().map { it.keyAttestation.value }.takeIf { it.isNotEmpty() },
            )
    }
}

@Serializable
internal data class CredentialResponseSuccessTO(
    @SerialName("credentials") val credentials: List<JsonObject>? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("interval") val interval: Long? = null,
    @SerialName("notification_id") val notificationId: String? = null,
) {
    init {
        if (!credentials.isNullOrEmpty()) {
            credentials.forEach {
                ensureNotNull(it.issuedCredential()) {
                    throw ResponseUnparsable("Credential must be either a string or a json object")
                }
            }
            ensure(interval == null && transactionId == null) {
                ResponseUnparsable("'transaction_id' or 'interval' cannot be present if 'credentials' is present")
            }
        }
        if (transactionId != null) {
            ensure(interval != null) {
                ResponseUnparsable("'transaction_id' received but 'interval' is missing")
            }
        }
        if (interval != null) {
            ensure(transactionId != null) {
                ResponseUnparsable("'interval' received but 'transaction_id' is missing")
            }
        }
        if (notificationId != null) {
            ensure(!credentials.isNullOrEmpty()) {
                ResponseUnparsable("'notification_id' can be present, if credentials is present")
            }
        }
    }

    fun toDomain(): SubmissionOutcomeInternal {
        val transactionId = transactionId?.let { TransactionId(it) }
        val notificationId = notificationId?.let(::NotificationId)

        val issuedCredentials =
            when {
                !credentials.isNullOrEmpty() -> credentials.map {
                    checkNotNull(it.issuedCredential())
                }

                else -> emptyList()
            }

        return when {
            issuedCredentials.isNotEmpty() -> SubmissionOutcomeInternal.Success(
                issuedCredentials,
                notificationId,
            )

            transactionId != null && interval != null -> SubmissionOutcomeInternal.Deferred(
                transactionId,
                interval.toDuration(DurationUnit.SECONDS),
            )
            else -> error("Cannot happen")
        }
    }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): CredentialResponseSuccessTO =
            JsonSupport.decodeFromString(JSONObjectUtils.toJSONString(jwtClaimsSet.toJSONObject()))
    }
}

private fun JsonObject.issuedCredential(): IssuedCredential? {
    fun credentialOf(json: JsonElement): Credential? = when {
        json is JsonPrimitive && json.isString -> Credential.Str(json.content)
        json is JsonObject && json.isNotEmpty() -> Credential.Json(json)
        else -> null
    }

    val credential = ensureNotNull(this["credential"]) {
        throw ResponseUnparsable("Missing 'credential' property from credential response")
    }
    val additionalInfo = JsonObject(filterKeys { it != "credential" })

    return credentialOf(credential)?.let { IssuedCredential(it, additionalInfo) }
}

//
// Deferred request / response
//

@Serializable
internal data class DeferredRequestTO(
    @SerialName("transaction_id") val transactionId: String,
    @SerialName("credential_response_encryption") val credentialResponseEncryption: CredentialResponseEncryptionSpecTO? = null,
) {
    companion object {
        fun toJwtClaimsSet(to: DeferredRequestTO): JWTClaimsSet =
            JWTClaimsSet.parse(JsonSupport.encodeToString(to))
    }
}

@Serializable
internal data class DeferredIssuanceSuccessResponseTO(
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("interval") val interval: Long? = null,
    @SerialName("credentials") val credentials: List<JsonObject>? = null,
    @SerialName("notification_id") val notificationId: String? = null,
) {
    fun toDomain(): DeferredCredentialQueryOutcome =
        when {
            transactionId != null && interval != null && credentials == null && notificationId == null -> {
                DeferredCredentialQueryOutcome.IssuancePending(TransactionId((transactionId)), interval.toDuration(DurationUnit.SECONDS))
            }

            transactionId == null && interval == null && !credentials.isNullOrEmpty() -> {
                val notificationId = notificationId?.let { NotificationId(it) }
                val credentials = credentials.map { requireNotNull(it.issuedCredential()) }
                DeferredCredentialQueryOutcome.Issued(credentials, notificationId)
            }

            else -> {
                throw ResponseUnparsable(
                    "Invalid deferred issuance response. " +
                        "Either 'transaction_id' and 'interval', or 'credentials' (potentially with 'notification_id') must be present," +
                        " but not all. TransactionId: $transactionId, interval: $interval, credentials: $credentials, " +
                        "notificationId: $notificationId",
                )
            }
        }

    companion object {
        fun from(jwtClaimsSet: JWTClaimsSet): DeferredIssuanceSuccessResponseTO =
            JsonSupport.decodeFromString(JSONObjectUtils.toJSONString(jwtClaimsSet.toJSONObject()))
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
) {

    fun toIssuanceError(): CredentialIssuanceError = when (error) {
        "invalid_proof" -> InvalidProof(errorDescription)
        "invalid_token" -> InvalidToken()
        "invalid_transaction_id " -> InvalidTransactionId()
        "unknown_credential_configuration " -> UnknownCredentialConfiguration()
        "unknown_credential_identifier " -> UnknownCredentialIdentifier()
        "invalid_encryption_parameters " -> InvalidEncryptionParameters()
        else -> IssuanceRequestFailed(error, errorDescription)
    }
}
