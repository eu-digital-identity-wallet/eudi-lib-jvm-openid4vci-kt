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

import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.call.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Serializable
sealed interface CredentialRequestTO {

    @Serializable
    data class BatchCredentialsTO(
        @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
    ) : CredentialRequestTO

    @Serializable
    data class DeferredCredentialTO(
        @SerialName("transaction_id") val transactionId: String,
    ) : CredentialRequestTO

    @Serializable
    sealed interface SingleCredentialTO : CredentialRequestTO {

        val format: String
        val proof: JsonObject?
        val credentialEncryptionJwk: JsonObject?
        val credentialResponseEncryptionAlg: String?
        val credentialResponseEncryptionMethod: String?

        @Serializable
        @SerialName("MsoMdoc")
        data class MsoMdocIssuanceRequestTO(
            @SerialName("format") override val format: String,
            @SerialName("doctype") val docType: String,
            @SerialName("proof") override val proof: JsonObject?,
            @SerialName("credential_encryption_jwk") override val credentialEncryptionJwk: JsonObject?,
            @SerialName("credential_response_encryption_alg") override val credentialResponseEncryptionAlg: String?,
            @SerialName("credential_response_encryption_enc") override val credentialResponseEncryptionMethod: String?,
            @SerialName("claims") val claims: JsonObject?,
        ) : SingleCredentialTO
    }
}

@Serializable
data class GenericErrorResponse(
    @SerialName("error") val error: String,
    @SerialName("error_description") val errorDescription: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
    @SerialName("interval") val interval: Long? = null,
)

@Serializable
data class SingleIssuanceSuccessResponse(
    @SerialName("format") val format: String,
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
data class BatchIssuanceSuccessResponse(
    @SerialName("credential_responses") val credentialResponses: List<CertificateIssuanceResponse>,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
) {
    @Serializable
    data class CertificateIssuanceResponse(
        @SerialName("format") val format: String,
        @SerialName("credential") val credential: String? = null,
        @SerialName("transaction_id") val transactionId: String? = null,
    )
}

internal class DefaultIssuanceRequester(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val issuerMetadata: CredentialIssuerMetadata,
    val postIssueRequest: HttpPost<CredentialRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
) : IssuanceRequester {

    override suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential,
    ): Result<CredentialIssuanceResponse> =
        runCatching {
            withContext(coroutineDispatcher) {
                postIssueRequest.post(
                    issuerMetadata.credentialEndpoint.value.value.toURL(),
                    mapOf(accessToken.toAuthorizationHeader()),
                    request.toTO(),
                ) {
                    // Process response
                    if (it.status.isSuccess()) {
                        if (request.requiresEncryptedResponse()) {
                            TODO("NOT IMPLEMENTED: Decrypt JWT, extract JWT claims and map them to IssuanceResponse")
                        } else {
                            val success = it.body<SingleIssuanceSuccessResponse>()
                            success.toSingleIssuanceResponse()
                        }
                    } else {
                        val error = it.body<GenericErrorResponse>()
                        error.toIssuanceError().raise()
                    }
                }
            }
        }

    override suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials,
    ): Result<CredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.batchCredentialEndpoint == null) {
            CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance.raise()
        }
        withContext(coroutineDispatcher) {
            postIssueRequest.post(
                issuerMetadata.batchCredentialEndpoint.value.value.toURL(),
                mapOf(accessToken.toAuthorizationHeader()),
                request.toTO(),
            ) {
                // Process response
                if (it.status.isSuccess()) {
                    // TODO: Handle encrypted responses
                    val success = it.body<BatchIssuanceSuccessResponse>()
                    success.toBatchIssuanceResponse()
                } else {
                    val error = it.body<GenericErrorResponse>()
                    error.toIssuanceError().raise()
                }
            }
        }
    }

    override suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        request: DeferredCredentialRequest,
    ): CredentialIssuanceResponse {
        TODO("Integration with Deferred Credential Endpoint not yet implemented")
    }
}

private fun SingleIssuanceSuccessResponse.toSingleIssuanceResponse(): CredentialIssuanceResponse =
    transactionId?.let {
        CredentialIssuanceResponse(
            cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
            credentialResponses = listOf(CredentialIssuanceResponse.Result.Deferred(transactionId)),
        )
    } ?: credential?.let {
        CredentialIssuanceResponse(
            cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
            credentialResponses = listOf(CredentialIssuanceResponse.Result.Complete(format, credential)),
        )
    }
        ?: CredentialIssuanceError.ResponseUnparsable(
            "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
        ).raise()

private fun BatchIssuanceSuccessResponse.toBatchIssuanceResponse(): CredentialIssuanceResponse {
    fun mapResults() = credentialResponses.map {
        it.transactionId?.let {
            CredentialIssuanceResponse.Result.Deferred(it)
        } ?: it.credential?.let { credential ->
            CredentialIssuanceResponse.Result.Complete(it.format, credential)
        }
            ?: CredentialIssuanceError.ResponseUnparsable(
                "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
            ).raise()
    }

    fun mapCNonce() = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }

    return CredentialIssuanceResponse(
        credentialResponses = mapResults(),
        cNonce = mapCNonce(),
    )
}

private fun GenericErrorResponse.toIssuanceError(): CredentialIssuanceError =
    when (error) {
        "invalid_proof" -> {
            cNonce?.let {
                CredentialIssuanceError.InvalidProof(
                    cNonce = cNonce,
                    cNonceExpiresIn = cNonceExpiresInSeconds,
                )
            }
                ?: CredentialIssuanceError.ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")
        }

        "issuance_pending" -> {
            interval?.let {
                CredentialIssuanceError.DeferredCredentialIssuancePending(interval)
            }
                ?: CredentialIssuanceError.DeferredCredentialIssuancePending()
        }

        "invalid_token" -> CredentialIssuanceError.InvalidToken
        "invalid_transaction_id " -> CredentialIssuanceError.InvalidTransactionId
        "unsupported_credential_type " -> CredentialIssuanceError.UnsupportedCredentialType
        "unsupported_credential_format " -> CredentialIssuanceError.UnsupportedCredentialFormat
        "invalid_encryption_parameters " -> CredentialIssuanceError.InvalidEncryptionParameters

        else -> CredentialIssuanceError.IssuanceRequestFailed(error, errorDescription)
    }

private fun IssuanceAccessToken.toAuthorizationHeader(): Pair<String, String> = "Authorization" to "BEARER $accessToken"

private fun CredentialIssuanceRequest.SingleCredential.toTO(): CredentialRequestTO.SingleCredentialTO {
    return when (this) {
        is CredentialIssuanceRequest.SingleCredential.MsoMdocIssuanceRequest ->
            CredentialRequestTO.SingleCredentialTO.MsoMdocIssuanceRequestTO(
                format = "mso_mdoc",
                docType = doctype,
                proof = proof?.toJsonObject(),
                credentialEncryptionJwk = credentialEncryptionJwk?.let {
                    Json.parseToJsonElement(
                        it.toPublicJWK().toString(),
                    ).jsonObject
                },
                credentialResponseEncryptionAlg = credentialResponseEncryptionAlg?.toString(),
                credentialResponseEncryptionMethod = credentialResponseEncryptionMethod?.toString(),
                claims = claimSet?.let {
                    Json.encodeToJsonElement(it.claims).jsonObject
                },
            )
    }
}

private fun CredentialIssuanceRequest.BatchCredentials.toTO(): CredentialRequestTO {
    return CredentialRequestTO.BatchCredentialsTO(
        credentialRequests = credentialRequests.map { it.toTO() },
    )
}
