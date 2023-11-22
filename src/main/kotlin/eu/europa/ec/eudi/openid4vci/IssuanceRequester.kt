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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DeferredIssuanceRequestTO(
    @SerialName("transaction_id") val transactionId: String,
)

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

@Serializable
data class DeferredIssuanceSuccessResponse(
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
 * @param credentialResponses The outcome of the issuance request. If issuance request was a batch request it will contain
 *      the results of each individual issuance request. If it was a single issuance request list will contain only one result.
 * @param cNonce Nonce information sent back from issuance server.
 */
data class CredentialIssuanceResponse(
    val credentialResponses: List<Result>,
    val cNonce: CNonce?,
) {
    /**
     * The result of a request for issuance
     */
    sealed interface Result {

        /**
         * Credential was issued from server and the result is returned inline.
         *
         * @param format The format of the issued credential
         * @param credential The issued credential
         */
        data class Issued(
            val format: String,
            val credential: String,
        ) : Result

        /**
         * Credential could not be issued immediately. An identifier is returned from server to be used later on
         * to request the credential from issuer's Deferred Credential Endpoint.
         *
         * @param transactionId  A string identifying a Deferred Issuance transaction.
         */
        data class Deferred(
            val transactionId: TransactionId,
        ) : Result
    }
}

sealed interface DeferredCredentialIssuanceResponse {

    data class Issued(
        val format: String,
        val credential: String,
    ) : DeferredCredentialIssuanceResponse

    data class IssuancePending(
        val transactionId: TransactionId,
    ) : DeferredCredentialIssuanceResponse

    data class Errored(
        val error: String,
        val errorDescription: String? = null,
    ) : DeferredCredentialIssuanceResponse
}

/**
 * Interface that specifies the interaction with a Credentials Issuer required to handle the issuance of a credential
 */
interface IssuanceRequester {

    val issuerMetadata: CredentialIssuerMetadata

    /**
     * Method that submits a request to credential issuer for the issuance of single credential.
     *
     * @param accessToken Access token authorizing the request
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential,
    ): Result<CredentialIssuanceResponse>

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param accessToken Access token authorizing the request
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials,
    ): Result<CredentialIssuanceResponse>

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param accessToken Access token authorizing the request
     * @param transactionId The identifier of the Deferred Issuance transaction
     * @return response from issuer. Can be either positive if credential is issued or errored in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialIssuanceResponse>

    companion object {

        /**
         * Factory method to create a default implementation of the [IssuanceRequester] interface.
         *
         * @param issuerMetadata  The credential issuer's metadata.
         * @param ktorHttpClientFactory Factory method to generate ktor http clients
         * @return A default implementation of the [IssuanceRequester] interface.
         */
        fun make(
            issuerMetadata: CredentialIssuerMetadata,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultIssuanceRequester.HttpClientFactory,
        ): IssuanceRequester =
            DefaultIssuanceRequester(
                issuerMetadata = issuerMetadata,
                ktorHttpClientFactory = ktorHttpClientFactory,
            )
    }
}
