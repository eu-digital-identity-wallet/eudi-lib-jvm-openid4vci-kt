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
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorIssuanceRequester
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject

@Serializable
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("format")
sealed interface CredentialIssuanceRequestTO {

    @Serializable
    @SerialName("batch-credential-request")
    data class BatchCredentialsTO(
        @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
    ) : CredentialIssuanceRequestTO

    @Serializable
    sealed interface SingleCredentialTO : CredentialIssuanceRequestTO {
        val proof: JsonObject?
        val credentialEncryptionJwk: JsonObject?
        val credentialResponseEncryptionAlg: String?
        val credentialResponseEncryptionMethod: String?
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

/**
 * Credential(s) issuance request
 */
sealed interface CredentialIssuanceRequest {

    /**
     * Models an issuance request for a batch of credentials
     */
    data class BatchCredentials(
        val credentialRequests: List<SingleCredential>,
    ) : CredentialIssuanceRequest

    /**
     * Models an issuance request for a single credential
     */
    sealed interface SingleCredential : CredentialIssuanceRequest {

        val format: String
        val proof: Proof?
        val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption

        companion object {
            fun requestedCredentialResponseEncryption(
                credentialEncryptionJwk: JWK?,
                credentialResponseEncryptionAlg: JWEAlgorithm?,
                credentialResponseEncryptionMethod: EncryptionMethod?,
            ): RequestedCredentialResponseEncryption =
                if (credentialEncryptionJwk == null &&
                    credentialResponseEncryptionAlg == null &&
                    credentialResponseEncryptionMethod == null
                ) {
                    RequestedCredentialResponseEncryption.NotRequested
                } else {
                    var encryptionMethod = credentialResponseEncryptionMethod
                    when {
                        credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null ->
                            encryptionMethod = EncryptionMethod.A256GCM
                        credentialResponseEncryptionAlg != null && credentialEncryptionJwk == null ->
                            throw CredentialIssuanceError.InvalidIssuanceRequest("Encryption algorithm was provided but no encryption key")
                        credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null ->
                            throw CredentialIssuanceError.InvalidIssuanceRequest(
                                "Credential response encryption algorithm must be specified if Credential " +
                                    "response encryption method is provided",
                            )
                    }
                    RequestedCredentialResponseEncryption.Requested(
                        encryptionJwk = credentialEncryptionJwk!!,
                        responseEncryptionAlg = credentialResponseEncryptionAlg!!,
                        responseEncryptionMethod = encryptionMethod!!,
                    )
                }
        }
    }
}

sealed interface RequestedCredentialResponseEncryption : java.io.Serializable {
    data object NotRequested : RequestedCredentialResponseEncryption {
        private fun readResolve(): Any = NotRequested
    }

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

data class DeferredCredentialRequest(
    val transactionId: String,
    val token: IssuanceAccessToken,
)

data class CredentialIssuanceResponse(
    val credentialResponses: List<Result>,
    val cNonce: CNonce?,
) {
    sealed interface Result {
        data class Issued(
            val format: String,
            val credential: String,
        ) : Result

        data class Deferred(
            val transactionId: String,
        ) : Result
    }
}

sealed interface ClaimSet

/**
 * Interface that specifies the interaction with a Credentials Issuer required to handle the issuance of a credential
 */
interface IssuanceRequester {

    val issuerMetadata: CredentialIssuerMetadata

    /**
     * Method that submits a request to credential issuer for the issuance of single credential.
     *
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
     * @param request The deferred credential request
     * @return response from issuer. Can be either positive if credential is issued or errored in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        request: DeferredCredentialRequest,
    ): CredentialIssuanceResponse

    companion object {
        fun make(
            issuerMetadata: CredentialIssuerMetadata,
            postIssueRequest: HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
        ): IssuanceRequester =
            DefaultIssuanceRequester(
                issuerMetadata = issuerMetadata,
                postIssueRequest = postIssueRequest,
            )
        fun ktor(
            issuerMetadata: CredentialIssuerMetadata,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
        ): IssuanceRequester =
            KtorIssuanceRequester(
                issuerMetadata = issuerMetadata,
                coroutineDispatcher = coroutineDispatcher,
            )
    }
}
