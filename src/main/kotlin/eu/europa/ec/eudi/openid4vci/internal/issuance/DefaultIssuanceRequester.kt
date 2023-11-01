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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequest.BatchCredentials
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceRequest.SingleCredential
import io.ktor.client.call.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*

internal class DefaultIssuanceRequester(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val issuerMetadata: CredentialIssuerMetadata,
    val postIssueRequest: HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
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
                    throw error.toIssuanceError()
                }
            }
        }
    }

    override suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: BatchCredentials,
    ): Result<CredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.batchCredentialEndpoint == null) {
            throw CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance
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
                    throw error.toIssuanceError()
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
        ?: throw CredentialIssuanceError.ResponseUnparsable(
            "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
        )

private fun BatchIssuanceSuccessResponse.toBatchIssuanceResponse(): CredentialIssuanceResponse {
    fun mapResults() = credentialResponses.map { res ->
        res.transactionId
            ?.let { CredentialIssuanceResponse.Result.Deferred(it) }
            ?: res.credential?.let { credential -> CredentialIssuanceResponse.Result.Complete(res.format, credential) }
            ?: throw CredentialIssuanceError.ResponseUnparsable(
                "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
            )
    }

    fun mapCNonce() = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) }

    return CredentialIssuanceResponse(
        credentialResponses = mapResults(),
        cNonce = mapCNonce(),
    )
}

private fun GenericErrorResponse.toIssuanceError(): CredentialIssuanceError =
    when (error) {
        "invalid_proof" ->
            cNonce
                ?.let {
                    CredentialIssuanceError.InvalidProof(
                        cNonce = cNonce,
                        cNonceExpiresIn = cNonceExpiresInSeconds,
                        errorDescription = errorDescription,
                    )
                }
                ?: CredentialIssuanceError.ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")

        "issuance_pending" ->
            interval
                ?.let { CredentialIssuanceError.DeferredCredentialIssuancePending(interval) }
                ?: CredentialIssuanceError.DeferredCredentialIssuancePending()

        "invalid_token" -> CredentialIssuanceError.InvalidToken
        "invalid_transaction_id " -> CredentialIssuanceError.InvalidTransactionId
        "unsupported_credential_type " -> CredentialIssuanceError.UnsupportedCredentialType
        "unsupported_credential_format " -> CredentialIssuanceError.UnsupportedCredentialFormat
        "invalid_encryption_parameters " -> CredentialIssuanceError.InvalidEncryptionParameters

        else -> CredentialIssuanceError.IssuanceRequestFailed(error, errorDescription)
    }

private fun IssuanceAccessToken.toAuthorizationHeader(): Pair<String, String> =
    "Authorization" to "BEARER $accessToken"

private fun SingleCredential.toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
    when (this) {
        is MsoMdocProfile.CredentialIssuanceRequest -> MsoMdocProfile.CredentialIssuanceRequestTO(
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
                Json.encodeToJsonElement(it).jsonObject
            },
        )

        is SdJwtVcProfile.CredentialIssuanceRequest -> SdJwtVcProfile.CredentialIssuanceRequestTO(
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

private fun Proof.toJsonObject(): JsonObject = when (this) {
    is Proof.Jwt -> {
        JsonObject(
            mapOf(
                "proof_type" to JsonPrimitive("jwt"),
                "jwt" to JsonPrimitive(jwt.serialize()),
            ),
        )
    }

    is Proof.Cwt -> {
        JsonObject(
            mapOf(
                "proof_type" to JsonPrimitive("cwt"),
                "jwt" to JsonPrimitive(cwt),
            ),
        )
    }
}

private fun BatchCredentials.toTransferObject(): CredentialIssuanceRequestTO =
    CredentialIssuanceRequestTO.BatchCredentialsTO(
        credentialRequests = credentialRequests.map { it.toTransferObject() },
    )
