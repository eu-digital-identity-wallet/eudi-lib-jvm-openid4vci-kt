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
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.BatchCredentials
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.SingleCredential
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

/**
 * Default implementation of [IssuanceRequester] interface.
 */
internal class DefaultIssuanceRequester(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    override val issuerMetadata: CredentialIssuerMetadata,
    val ktorHttpClientFactory: KtorHttpClientFactory = HttpClientFactory,
) : IssuanceRequester {

    override suspend fun placeIssuanceRequest(
        accessToken: AccessToken,
        request: SingleCredential,
    ): Result<CredentialIssuanceResponse> = withContext(coroutineDispatcher) {
        runCatching {
            ktorHttpClientFactory().use { client ->
                postIssuanceRequest(client).post(
                    issuerMetadata.credentialEndpoint.value.value.toURL(),
                    mapOf(accessToken.toAuthorizationHeader()),
                    request.toTransferObject(),
                ) {
                    handleResponseSingle(it, request)
                }
            }
        }
    }

    override suspend fun placeBatchIssuanceRequest(
        accessToken: AccessToken,
        request: BatchCredentials,
    ): Result<CredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.batchCredentialEndpoint == null) {
            throw IssuerDoesNotSupportBatchIssuance
        }
        withContext(coroutineDispatcher) {
            ktorHttpClientFactory().use { client ->
                postIssuanceRequest(client).post(
                    issuerMetadata.batchCredentialEndpoint.value.value.toURL(),
                    mapOf(accessToken.toAuthorizationHeader()),
                    request.toTransferObject(),
                ) {
                    handleResponseBatch(it)
                }
            }
        }
    }

    private suspend inline fun handleResponseSingle(
        response: HttpResponse,
        request: SingleCredential,
    ): CredentialIssuanceResponse =
        if (response.status.isSuccess()) {
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
        accessToken: AccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        if (issuerMetadata.deferredCredentialEndpoint == null) {
            throw IssuerDoesNotSupportDeferredIssuance
        }
        withContext(coroutineDispatcher) {
            ktorHttpClientFactory().use { client ->
                postDeferredIssuanceRequest(client).post(
                    issuerMetadata.deferredCredentialEndpoint.value.value.toURL(),
                    mapOf(accessToken.toAuthorizationHeader()),
                    transactionId.toDeferredRequestTO(),
                ) { handleResponseDeferred(it) }
            }
        }
    }

    private fun TransactionId.toDeferredRequestTO(): DeferredIssuanceRequestTO = DeferredIssuanceRequestTO(value)

    private suspend inline fun handleResponseDeferred(
        response: HttpResponse,

    ): DeferredCredentialQueryOutcome =
        if (response.status.isSuccess()) {
            val success = response.body<DeferredIssuanceSuccessResponse>()
            DeferredCredentialQueryOutcome.Issued(
                IssuedCredential.Issued(
                    format = success.format,
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

    private fun SingleIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse =
        transactionId?.let {
            CredentialIssuanceResponse(
                cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
                credentials = listOf(IssuedCredential.Deferred(TransactionId(transactionId))),
            )
        } ?: credential?.let {
            CredentialIssuanceResponse(
                cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
                credentials = listOf(IssuedCredential.Issued(format, credential)),
            )
        } ?: throw ResponseUnparsable(
            "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
        )

    private fun BatchIssuanceSuccessResponse.toDomain(): CredentialIssuanceResponse =
        CredentialIssuanceResponse(
            cNonce = cNonce?.let { CNonce(cNonce, cNonceExpiresInSeconds) },
            credentials = credentialResponses.map {
                it.transactionId?.let {
                    IssuedCredential.Deferred(TransactionId(it))
                } ?: it.credential?.let { credential ->
                    IssuedCredential.Issued(it.format, credential)
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

    private fun AccessToken.toAuthorizationHeader(): Pair<String, String> =
        "Authorization" to "BEARER $accessToken"

    private fun BatchCredentials.toTransferObject(): CredentialIssuanceRequestTO {
        return CredentialIssuanceRequestTO.BatchCredentialsTO(
            credentialRequests = credentialRequests.map { it.toTransferObject() },
        )
    }

    companion object {
        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val HttpClientFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = Json { ignoreUnknownKeys = true },
                    )
                }
            }
        }

        private fun postIssuanceRequest(httpClient: HttpClient):
            HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse> =
            HttpPost { url, headers, payload, responseHandler ->
                val response = httpClient.post(url) {
                    headers {
                        headers.forEach { (k, v) -> append(k, v) }
                    }
                    contentType(ContentType.parse("application/json"))
                    setBody(payload)
                }
                responseHandler(response)
            }

        private fun postDeferredIssuanceRequest(httpClient: HttpClient):
            HttpPost<DeferredIssuanceRequestTO, DeferredCredentialQueryOutcome, DeferredCredentialQueryOutcome> =
            HttpPost { url, headers, payload, responseHandler ->
                val response = httpClient.post(url) {
                    headers {
                        headers.forEach { (k, v) -> append(k, v) }
                    }
                    contentType(ContentType.parse("application/json"))
                    setBody(payload)
                }
                responseHandler(response)
            }
    }
}
