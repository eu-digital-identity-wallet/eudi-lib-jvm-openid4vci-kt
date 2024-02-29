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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.formats.IssuanceRequestJsonMapper
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
internal data class DeferredIssuanceRequestTO(
    @SerialName("transaction_id") val transactionId: String,
)

@Serializable
private data class GenericErrorResponse(
    @SerialName("error") val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
    @SerialName("interval") val interval: Long? = null,
)

@Serializable
private data class SingleIssuanceSuccessResponse(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("notification_id") val notificationId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
internal data class CertificateIssuanceResponse(
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
)

@Serializable
internal data class BatchIssuanceSuccessResponse(
    @SerialName("credential_responses") val credentialResponses: List<CertificateIssuanceResponse>,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
private data class DeferredIssuanceSuccessResponse(
    @SerialName("credential") val credential: String,
)

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

/**
 * Default implementation of [IssuanceRequester] interface.
 */
internal class IssuanceRequester(
    private val issuerMetadata: CredentialIssuerMetadata,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
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
    ): Result<CredentialIssuanceResponse> =
        runCatching {
            ktorHttpClientFactory().use { client ->
                val url = issuerMetadata.credentialEndpoint.value.value
                val response = client.post(url) {
                    bearerAuth(accessToken.accessToken)
                    contentType(ContentType.Application.Json)
                    setBody(IssuanceRequestJsonMapper.asJson(request))
                }
                handleResponseSingle(response, request)
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
                bearerAuth(accessToken.accessToken)
                contentType(ContentType.Application.Json)
                setBody(payload)
            }
            handleResponseBatch(response)
        }
    }

    private suspend inline fun handleResponseSingle(
        response: HttpResponse,
        request: CredentialIssuanceRequest.SingleRequest,
    ): CredentialIssuanceResponse =
        if (response.status.isSuccess()) {
            when (issuerMetadata.credentialResponseEncryption) {
                is CredentialResponseEncryption.NotRequired -> {
                    val success = response.body<SingleIssuanceSuccessResponse>()
                    success.toDomain()
                }

                is CredentialResponseEncryption.Required -> {
                    val jwt = response.body<String>()
                    val encryptionSpec = ensureNotNull(request.encryption) {
                        IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
                    }

                    DefaultJWTProcessor<SecurityContext>().apply {
                        jweKeySelector = JWEDecryptionKeySelector(
                            encryptionSpec.algorithm,
                            encryptionSpec.encryptionMethod,
                            ImmutableJWKSet(JWKSet(encryptionSpec.jwk)),
                        )
                    }.process(jwt, null)
                        .toSingleIssuanceSuccessResponse()
                        .toDomain()
                }
            }
        } else {
            val error = response.body<GenericErrorResponse>()
            throw error.toIssuanceError()
        }

    private fun JWTClaimsSet.toSingleIssuanceSuccessResponse(): SingleIssuanceSuccessResponse =
        SingleIssuanceSuccessResponse(
            credential = getStringClaim("credential"),
            transactionId = getStringClaim("transaction_id"),
            notificationId = getStringClaim("notification_id"),
            cNonce = getStringClaim("c_nonce"),
            cNonceExpiresInSeconds = getLongClaim("c_nonce_expires_in"),
        )

    private suspend inline fun handleResponseBatch(response: HttpResponse): CredentialIssuanceResponse =
        if (response.status.isSuccess()) {
            when (issuerMetadata.credentialResponseEncryption) {
                is CredentialResponseEncryption.NotRequired -> {
                    val success = response.body<BatchIssuanceSuccessResponse>()
                    success.toDomain()
                }

                is CredentialResponseEncryption.Required -> {
                    TODO("ENCRYPTED RESPONSES OF BATCH ISSUANCE NOT YET SUPPORTED")
                }
            }
        } else {
            val error = response.body<GenericErrorResponse>()
            throw error.toIssuanceError()
        }

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param transactionId The identifier of the Deferred Issuance transaction
     * @return response from issuer. Can be either positive if a credential is issued or error in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        ensureNotNull(issuerMetadata.deferredCredentialEndpoint) { IssuerDoesNotSupportDeferredIssuance }
        ktorHttpClientFactory().use { client ->
            val url = issuerMetadata.deferredCredentialEndpoint.value.value
            val response = client.post(url) {
                bearerAuth(accessToken.accessToken)
                contentType(ContentType.Application.Json)
                setBody(transactionId.toDeferredRequestTO())
            }
            handleResponseDeferred(response)
        }
    }

    private fun TransactionId.toDeferredRequestTO(): DeferredIssuanceRequestTO =
        DeferredIssuanceRequestTO(value)

    private suspend inline fun handleResponseDeferred(
        response: HttpResponse,

    ): DeferredCredentialQueryOutcome =
        if (response.status.isSuccess()) {
            val success = response.body<DeferredIssuanceSuccessResponse>()
            DeferredCredentialQueryOutcome.Issued(
                IssuedCredential.Issued(
                    credential = success.credential,
                ),
            )
        } else {
            val responsePayload = response.body<GenericErrorResponse>()
            when (responsePayload.error) {
                "issuance_pending" -> DeferredCredentialQueryOutcome.IssuancePending(responsePayload.interval)
                else -> DeferredCredentialQueryOutcome.Errored(
                    responsePayload.error,
                    responsePayload.errorDescription,
                )
            }
        }

    private fun SingleIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        val issuedCredential = issuedCredentialOf(transactionId, credential)
        return CredentialIssuanceResponse(
            cNonce = cNonce,
            credentials = listOf(issuedCredential),
        )
    }

    private fun issuedCredentialOf(
        transactionId: String?,
        credential: String?,
    ): IssuedCredential {
        ensure(!(transactionId == null && credential == null)) {
            val error =
                "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters"
            ResponseUnparsable(error)
        }
        return when {
            transactionId != null -> IssuedCredential.Deferred(TransactionId(transactionId))
            credential != null -> IssuedCredential.Issued(credential)
            else -> error("Cannot happen")
        }
    }

    private fun BatchIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse {
        val cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }
        return CredentialIssuanceResponse(
            cNonce = cNonce,
            credentials = credentialResponses.map { issuedCredentialOf(it.transactionId, it.credential) },
        )
    }

    private fun GenericErrorResponse.toIssuanceError(): CredentialIssuanceError = when (error) {
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
}
