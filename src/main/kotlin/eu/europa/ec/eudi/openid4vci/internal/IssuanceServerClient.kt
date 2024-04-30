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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.*
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.formats.IssuanceRequestJsonMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
private data class GenericErrorResponseTO(
    @SerialName("error") val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
    @SerialName("interval") val interval: Long? = null,
)

@Serializable
private data class IssuanceSuccessResponseTO(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
internal data class IssuanceResponseTO(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
)

@Serializable
internal data class BatchIssuanceSuccessResponseTO(
    @SerialName("credential_responses") val credentialResponses: List<IssuanceResponseTO>,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
private data class DeferredIssuanceSuccessResponseTO(
    @SerialName("credential") val credential: String,
)

@Serializable
internal class NotificationTO(
    @SerialName("notification_id") val id: String,
    @SerialName("event") val event: NotificationEventTO,
    @SerialName("event_description") val description: String? = null,
)

@Serializable
internal enum class NotificationEventTO {
    @SerialName("credential_accepted")
    CREDENTIAL_ACCEPTED,

    @SerialName("credential_failure")
    CREDENTIAL_FAILURE,

    @SerialName("credential_deleted")
    CREDENTIAL_DELETED,
}

/**
 * Models a response of the issuer to a successful issuance request.
 *
 * @param credentials The outcome of the issuance request.
 * if the issuance request was a batch request, it will contain
 * the results of each issuance request.
 * If it was a single issuance request list will contain only one result.
 * @param cNonce Nonce information sent back from the issuance server.
 */
internal data class CredentialIssuanceResponse(
    val credentials: List<IssuedCredential>,
    val cNonce: CNonce?,
)

internal class IssuanceServerClient(
    private val issuerMetadata: CredentialIssuerMetadata,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
    private val dPoPJwtFactory: DPoPJwtFactory?,
) {

    /**
     * Method that submits a request to credential issuer for the issuance of a single credential.
     *
     * @param accessToken Access token authorizing the request
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest.SingleRequest,
    ): Result<CredentialIssuanceResponse> = runCatching {
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.credentialEndpoint.value.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(IssuanceRequestJsonMapper.asJson(request))
            }
            handleResponseSingle(response, request.encryption)
        }
    }

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param accessToken Access token authorizing the request
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest.BatchRequest,
    ): Result<CredentialIssuanceResponse> = runCatching {
        ensureNotNull(issuerMetadata.batchCredentialEndpoint) { IssuerDoesNotSupportBatchIssuance }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.batchCredentialEndpoint.value.value
            val payload = IssuanceRequestJsonMapper.asJson(request)
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
            // TODO pass responseEncryptionSpec
            handleResponseBatch(response, null)
        }
    }

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param deferredCredential The identifier of the Deferred Issuance transaction
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        deferredCredential: IssuedCredential.Deferred,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        ensureNotNull(issuerMetadata.deferredCredentialEndpoint) { IssuerDoesNotSupportDeferredIssuance }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.deferredCredentialEndpoint.value.value
            val request = IssuanceRequestJsonMapper.asJson(deferredCredential, responseEncryptionSpec)
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(request)
            }
            handleResponseDeferred(response, responseEncryptionSpec)
        }
    }

    suspend fun notifyIssuer(
        accessToken: AccessToken,
        event: CredentialIssuanceEvent,
    ): Result<Unit> = runCatching {
        ensureNotNull(issuerMetadata.notificationEndpoint) { IssuerDoesNotSupportNotifications }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.notificationEndpoint.value.value
            val payload = event.toTransferObject()
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
            if (response.status.isSuccess()) {
                Unit
            } else {
                val errorResponse = response.body<GenericErrorResponseTO>()
                throw NotificationFailed(errorResponse.error)
            }
        }
    }
}

private suspend fun handleResponseSingle(
    response: HttpResponse,
    responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
): CredentialIssuanceResponse {
    fun JWTClaimsSet.toTransferObject(): IssuanceSuccessResponseTO =
        IssuanceSuccessResponseTO(
            credential = getStringClaim("credential"),
            transactionId = getStringClaim("transaction_id"),
            notificationId = getStringClaim("notification_id"),
            cNonce = getStringClaim("c_nonce"),
            cNonceExpiresInSeconds = getLongClaim("c_nonce_expires_in"),
        )

    fun IssuanceSuccessResponseTO.fromTransferObject(): CredentialIssuanceResponse {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        val issuedCredential = issuedCredentialOf(transactionId, notificationId, credential)
        return CredentialIssuanceResponse(
            cNonce = cNonce,
            credentials = listOf(issuedCredential),
        )
    }

    return if (response.status.isSuccess()) {
        handlePossiblyEncrypted(
            response,
            responseEncryptionSpec,
            fromTransferObject = { it.fromTransferObject() },
            transferObjectFromJwtClaims = { it.toTransferObject() },
        )
    } else {
        val error = response.body<GenericErrorResponseTO>()
        throw error.toIssuanceError()
    }
}

private suspend fun handleResponseBatch(
    response: HttpResponse,
    responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
): CredentialIssuanceResponse {
    fun BatchIssuanceSuccessResponseTO.toDomain(): CredentialIssuanceResponse {
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
    fun JWTClaimsSet.fromJwtClaims(): BatchIssuanceSuccessResponseTO = TODO()

    return if (response.status.isSuccess()) {
        handlePossiblyEncrypted(
            response,
            responseEncryptionSpec,
            fromTransferObject = { it.toDomain() },
            transferObjectFromJwtClaims = { it.fromJwtClaims() },
        )
    } else {
        val error = response.body<GenericErrorResponseTO>()
        throw error.toIssuanceError()
    }
}

private suspend fun handleResponseDeferred(
    response: HttpResponse,
    responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
): DeferredCredentialQueryOutcome {
    fun DeferredIssuanceSuccessResponseTO.toDomain(): DeferredCredentialQueryOutcome.Issued {
        return DeferredCredentialQueryOutcome.Issued(IssuedCredential.Issued(credential))
    }
    fun JWTClaimsSet.fromJwtClaims(): DeferredIssuanceSuccessResponseTO =
        DeferredIssuanceSuccessResponseTO(getStringClaim("credential"))

    return if (response.status.isSuccess()) {
        handlePossiblyEncrypted(
            response,
            responseEncryptionSpec,
            fromTransferObject = { it.toDomain() },
            transferObjectFromJwtClaims = { it.fromJwtClaims() },
        )
    } else {
        val responsePayload = response.body<GenericErrorResponseTO>()
        when (responsePayload.error) {
            "issuance_pending" -> DeferredCredentialQueryOutcome.IssuancePending(responsePayload.interval)
            else -> DeferredCredentialQueryOutcome.Errored(
                responsePayload.error,
                responsePayload.errorDescription,
            )
        }
    }
}

private suspend inline fun <reified ResponseJson, Response> handlePossiblyEncrypted(
    response: HttpResponse,
    encryptionSpec: IssuanceResponseEncryptionSpec?,
    fromTransferObject: (ResponseJson) -> Response,
    transferObjectFromJwtClaims: (JWTClaimsSet) -> ResponseJson,
): Response {
    check(response.status.isSuccess())
    val responseJson = when (encryptionSpec) {
        null -> response.body<ResponseJson>()
        else -> {
            val jwt = response.body<String>()
            val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
                jweKeySelector = JWEDecryptionKeySelector(
                    encryptionSpec.algorithm,
                    encryptionSpec.encryptionMethod,
                    ImmutableJWKSet(JWKSet(encryptionSpec.jwk)),
                )
            }
            val jwtClaimSet = jwtProcessor.process(jwt, null)
            transferObjectFromJwtClaims(jwtClaimSet)
        }
    }
    return fromTransferObject(responseJson)
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

private fun CredentialIssuanceEvent.toTransferObject(): NotificationTO =
    when (this) {
        is CredentialIssuanceEvent.Accepted -> NotificationTO(
            id = id.value,
            event = NotificationEventTO.CREDENTIAL_ACCEPTED,
            description = this.description,
        )

        is CredentialIssuanceEvent.Deleted -> NotificationTO(
            id = id.value,
            event = NotificationEventTO.CREDENTIAL_DELETED,
            description = this.description,
        )

        is CredentialIssuanceEvent.Failed -> NotificationTO(
            id = id.value,
            event = NotificationEventTO.CREDENTIAL_FAILURE,
            description = this.description,
        )
    }

private fun GenericErrorResponseTO.toIssuanceError(): CredentialIssuanceError = when (error) {
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
