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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.*
import eu.europa.ec.eudi.openid4vci.formats.CredentialIssuanceRequest.BatchCredentials
import eu.europa.ec.eudi.openid4vci.formats.CredentialIssuanceRequest.SingleCredential
import eu.europa.ec.eudi.openid4vci.formats.CredentialIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.formats.Formats
import io.ktor.client.call.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Default implementation of [IssuanceRequester] interface.
 */
internal class DefaultIssuanceRequester(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val issuerMetadata: CredentialIssuerMetadata,
    val postIssueRequest: HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
    val postDeferredIssueRequest:
        HttpPost<DeferredIssuanceRequestTO, DeferredCredentialIssuanceResponse, DeferredCredentialIssuanceResponse>,
) : IssuanceRequester {

    override suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: SingleCredential,
    ): Result<CredentialIssuanceResponse> = withContext(coroutineDispatcher) {
        runCatching {
            postIssueRequest.post(
                issuerMetadata.credentialEndpoint.value.value.toURL(),
                mapOf(accessToken.toAuthorizationHeader()),
                request.toTransferObject(),
            ) {
                handleResponseSingle(it, request)
            }
        }
    }

    override suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: BatchCredentials,
    ): Result<CredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.batchCredentialEndpoint == null) {
            throw IssuerDoesNotSupportBatchIssuance
        }
        withContext(coroutineDispatcher) {
            postIssueRequest.post(
                issuerMetadata.batchCredentialEndpoint.value.value.toURL(),
                mapOf(accessToken.toAuthorizationHeader()),
                request.toTransferObject(),
            ) {
                handleResponseBatch(it)
            }
        }
    }

    private suspend inline fun handleResponseSingle(
        response: HttpResponse,
        request: SingleCredential,
    ): CredentialIssuanceResponse = if (response.status.isSuccess()) {
        when (issuerMetadata.credentialResponseEncryption) {
            is CredentialResponseEncryption.NotRequired -> {
                val success = response.body<SingleIssuanceSuccessResponse>()
                success.toDomain()
            }

            is CredentialResponseEncryption.Required -> {
                val jwt = response.body<String>()
                val encryptionSpec =
                    when (val requestedEncryptionSpec = request.requestedCredentialResponseEncryption) {
                        is RequestedCredentialResponseEncryption.Requested -> requestedEncryptionSpec
                        is RequestedCredentialResponseEncryption.NotRequested ->
                            throw ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
                    }

                DefaultJWTProcessor<SecurityContext>().apply {
                    jweKeySelector = JWEDecryptionKeySelector(
                        encryptionSpec.responseEncryptionAlg,
                        encryptionSpec.responseEncryptionMethod,
                        ImmutableJWKSet(JWKSet(encryptionSpec.encryptionJwk)),
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
            format = getStringClaim("format"),
            credential = getStringClaim("credential"),
            transactionId = getStringClaim("transaction_id"),
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

    override suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.deferredCredentialEndpoint == null) {
            throw IssuerDoesNotSupportDeferredIssuance
        }
        withContext(coroutineDispatcher) {
            postDeferredIssueRequest.post(
                issuerMetadata.deferredCredentialEndpoint.value.value.toURL(),
                mapOf(accessToken.toAuthorizationHeader()),
                transactionId.toDeferredRequestTO(),
            ) {
                handleResponseDeferred(it, transactionId)
            }
        }
    }

    fun TransactionId.toDeferredRequestTO(): DeferredIssuanceRequestTO = DeferredIssuanceRequestTO(value)

    private suspend inline fun handleResponseDeferred(
        response: HttpResponse,
        transactionId: TransactionId,
    ): DeferredCredentialIssuanceResponse =
        if (response.status.isSuccess()) {
            val success = response.body<DeferredIssuanceSuccessResponse>()
            DeferredCredentialIssuanceResponse.Issued(
                format = success.format,
                credential = success.credential,
            )
        } else {
            val responsePayload = response.body<GenericErrorResponse>()
            when (responsePayload.error) {
                "issuance_pending" -> DeferredCredentialIssuanceResponse.IssuancePending(
                    TransactionId(transactionId.value, responsePayload.interval),
                )

                else -> DeferredCredentialIssuanceResponse.Errored(
                    responsePayload.error,
                    responsePayload.errorDescription,
                )
            }
        }

    private fun SingleIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse =
        transactionId?.let {
            CredentialIssuanceResponse(
                cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
                credentialResponses = listOf(CredentialIssuanceResponse.Result.Deferred(TransactionId(transactionId))),
            )
        } ?: credential?.let {
            CredentialIssuanceResponse(
                cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
                credentialResponses = listOf(CredentialIssuanceResponse.Result.Issued(format, credential)),
            )
        } ?: throw ResponseUnparsable(
            "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
        )

    private fun BatchIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse =
        CredentialIssuanceResponse(
            cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
            credentialResponses = credentialResponses.map {
                it.transactionId?.let {
                    CredentialIssuanceResponse.Result.Deferred(TransactionId(it))
                } ?: it.credential?.let { credential ->
                    CredentialIssuanceResponse.Result.Issued(it.format, credential)
                } ?: throw ResponseUnparsable(
                    "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
                )
            },
        )

    private fun GenericErrorResponse.toIssuanceError(): CredentialIssuanceError = when (error) {
        "invalid_proof" -> cNonce?.let {
            InvalidProof(
                cNonce = cNonce,
                cNonceExpiresIn = cNonceExpiresInSeconds,
                errorDescription = errorDescription,
            )
        }
            ?: ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")

        "issuance_pending" -> interval?.let { DeferredCredentialIssuancePending(interval) }
            ?: DeferredCredentialIssuancePending()

        "invalid_token" -> InvalidToken
        "invalid_transaction_id " -> InvalidTransactionId
        "unsupported_credential_type " -> UnsupportedCredentialType
        "unsupported_credential_format " -> UnsupportedCredentialFormat
        "invalid_encryption_parameters " -> InvalidEncryptionParameters

        else -> IssuanceRequestFailed(error, errorDescription)
    }

    private fun IssuanceAccessToken.toAuthorizationHeader(): Pair<String, String> =
        "Authorization" to "BEARER $accessToken"

    private fun SingleCredential.toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        Formats.mapRequestToTransferObject(this)

    private fun BatchCredentials.toTransferObject(): CredentialIssuanceRequestTO {
        return CredentialIssuanceRequestTO.BatchCredentialsTO(
            credentialRequests = credentialRequests.map { it.toTransferObject() },
        )
    }
}
