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
import io.ktor.util.reflect.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

internal class DefaultIssuanceRequester(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val issuerMetadata: CredentialIssuerMetadata,
    val postIssueRequest: HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
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
                    request.toTransferObject(),
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
                request.toTransferObject(),
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
        "invalid_proof",
        -> {
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

private fun CredentialIssuanceRequest.SingleCredential.toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO {
    return when (this) {
        is MsoMdocProfile.CredentialIssuanceRequest ->
            MsoMdocProfile.CredentialIssuanceRequestTO(
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

        is SdJwtVcProfile.CredentialIssuanceRequest ->
            SdJwtVcProfile.CredentialIssuanceRequestTO(
                proof = proof?.toJsonObject(),
                credentialEncryptionJwk = credentialEncryptionJwk?.let {
                    Json.parseToJsonElement(
                        it.toPublicJWK().toString(),
                    ).jsonObject
                },
                credentialResponseEncryptionAlg = credentialResponseEncryptionAlg?.toString(),
                credentialResponseEncryptionMethod = credentialResponseEncryptionMethod?.toString(),
                credentialDefinition = SdJwtVcProfile.CredentialIssuanceRequestTO.CredentialDefinitionTO(
                    type = credentialDefinition.type,
                    claims = credentialDefinition.claims?.let {
                        Json.encodeToJsonElement(it.claims).jsonObject
                    },
                ),
            )
    }
}

private fun CredentialIssuanceRequest.BatchCredentials.toTransferObject(): CredentialIssuanceRequestTO {
    return CredentialIssuanceRequestTO.BatchCredentialsTO(
        credentialRequests = credentialRequests.map { it.toTransferObject() },
    )
}
