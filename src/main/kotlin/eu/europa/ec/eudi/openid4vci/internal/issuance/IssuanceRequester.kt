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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.HttpPost
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
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
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

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
    @SerialName("format") val format: String,
    @SerialName("credential") val credential: String? = null,
    @SerialName("transaction_id") val transactionId: String? = null,
    @SerialName("c_nonce") val cNonce: String? = null,
    @SerialName("c_nonce_expires_in") val cNonceExpiresInSeconds: Long? = null,
)

@Serializable
internal data class BatchIssuanceSuccessResponse(
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

@Serializable
private data class DeferredIssuanceSuccessResponse(
    @SerialName("format") val format: String,
    @SerialName("credential") val credential: String,
)

/**
 * Sealed hierarchy for the issuance response encryption specification as it is requested to the issuer server.
 */
sealed interface RequestedCredentialResponseEncryption : java.io.Serializable {

    /**
     *  No encryption is requested
     */
    data object NotRequested : RequestedCredentialResponseEncryption {
        private fun readResolve(): Any = NotRequested
    }

    /**
     *  The encryption parameters that are sent along with the issuance request.
     *
     * @param encryptionJwk   Key pair in JWK format used for issuance response encryption/decryption
     * @param responseEncryptionAlg   Encryption algorithm to be used
     * @param responseEncryptionMethod Encryption method to be used
     */
    data class Requested(
        val encryptionJwk: JWK,
        val responseEncryptionAlg: JWEAlgorithm,
        val responseEncryptionMethod: EncryptionMethod,
    ) : RequestedCredentialResponseEncryption {
        init {
            // Validate algorithm provided is for asymmetric encryption
            check(JWEAlgorithm.Family.ASYMMETRIC.contains(responseEncryptionAlg)) {
                "Provided encryption algorithm is not an asymmetric encryption algorithm"
            }
            // Validate algorithm matches key
            check(encryptionJwk.keyType == KeyType.forAlgorithm(responseEncryptionAlg)) {
                "Encryption key and encryption algorithm do not match"
            }
            // Validate key is for encryption operation
            check(encryptionJwk.keyUse == KeyUse.ENCRYPTION) {
                "Provided key use is not encryption"
            }
        }
    }
}


/**
 * Models a response of the issuer to a successful issuance request.
 *
 * @param credentials The outcome of the issuance request. If issuance request was a batch request it will contain
 *      the results of each individual issuance request. If it was a single issuance request list will contain only one result.
 * @param cNonce Nonce information sent back from issuance server.
 */
internal data class CredentialIssuanceResponse(
    val credentials: List<IssuedCredential>,
    val cNonce: CNonce?,
)


/**
 * Factory method to create a default implementation of the [IssuanceRequester] interface.
 *
 * @param issuerMetadata  The credential issuer's metadata.
 * @param ktorHttpClientFactory Factory method to generate ktor http clients
 * @return A default implementation of the [IssuanceRequester] interface.
 */


/**
 * Default implementation of [IssuanceRequester] interface.
 */
internal class IssuanceRequester(
    private val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val issuerMetadata: CredentialIssuerMetadata,
    private val ktorHttpClientFactory: KtorHttpClientFactory = HttpClientFactory,
) {

    /**
     * Method that submits a request to credential issuer for the issuance of single credential.
     *
     * @param accessToken Access token authorizing the request
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest.SingleCredential,
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

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param accessToken Access token authorizing the request
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: AccessToken,
        request: CredentialIssuanceRequest.BatchCredentials,
    ): Result<CredentialIssuanceResponse> = runCatching {
        if (issuerMetadata.batchCredentialEndpoint == null) {
            throw CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance
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
        request: CredentialIssuanceRequest.SingleCredential,
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
                                throw CredentialIssuanceError.ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
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

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param transactionId The identifier of the Deferred Issuance transaction
     * @return response from issuer. Can be either positive if credential is issued or errored in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: AccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialQueryOutcome> = runCatching {
        if (issuerMetadata.deferredCredentialEndpoint == null) {
            throw CredentialIssuanceError.IssuerDoesNotSupportDeferredIssuance
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
        } ?: throw CredentialIssuanceError.ResponseUnparsable(
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
                } ?: throw CredentialIssuanceError.ResponseUnparsable(
                    "Got success response for issuance but response misses 'transaction_id' and 'certificate' parameters",
                )
            },
        )

    private fun GenericErrorResponse.toIssuanceError(): CredentialIssuanceError = when (error) {
        "invalid_proof" -> cNonce?.let {
            CredentialIssuanceError.InvalidProof(
                cNonce = cNonce,
                cNonceExpiresIn = cNonceExpiresInSeconds,
                errorDescription = errorDescription,
            )
        }
            ?: CredentialIssuanceError.ResponseUnparsable("Issuer responded with invalid_proof error but no c_nonce was provided")

        "issuance_pending" -> interval?.let { CredentialIssuanceError.DeferredCredentialIssuancePending(interval) }
            ?: CredentialIssuanceError.DeferredCredentialIssuancePending()

        "invalid_token" -> CredentialIssuanceError.InvalidToken
        "invalid_transaction_id " -> CredentialIssuanceError.InvalidTransactionId
        "unsupported_credential_type " -> CredentialIssuanceError.UnsupportedCredentialType
        "unsupported_credential_format " -> CredentialIssuanceError.UnsupportedCredentialFormat
        "invalid_encryption_parameters " -> CredentialIssuanceError.InvalidEncryptionParameters

        else -> CredentialIssuanceError.IssuanceRequestFailed(error, errorDescription)
    }

    private fun AccessToken.toAuthorizationHeader(): Pair<String, String> =
        "Authorization" to "BEARER $accessToken"

    private fun CredentialIssuanceRequest.BatchCredentials.toTransferObject(): CredentialIssuanceRequestTO {
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