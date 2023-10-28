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

import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuer

sealed interface UnauthorizedRequest {

    /**
     * State denoting that the pushed authorization request has been placed successfully and response processed
     */
    data class ParRequested(
        val credentials: List<CredentialMetadata>,
        val getAuthorizationCodeURL: GetAuthorizationCodeURL,
        val pkceVerifier: PKCEVerifier,
        val state: String,
    )

    /**
     * State denoting that caller has followed the [ParRequested.getAuthorizationCodeURL] URL and response received
     * from authorization server and processed successfully.
     */
    data class AuthorizationCodeRetrieved(
        val credentials: List<CredentialMetadata>,
        val authorizationCode: IssuanceAuthorization.AuthorizationCode,
        val pkceVerifier: PKCEVerifier,
    )
}

sealed interface AuthorizedRequest {

    val token: IssuanceAccessToken

    /**
     * Issuer authorized issuance
     *
     * @param token Access token authorizing certificate issuance
     */
    data class NoProofRequired(
        override val token: IssuanceAccessToken,
    ) : AuthorizedRequest

    /**
     * Issuer authorized issuance and requires the provision of proof of holder's binding to be provided
     * along with the request
     *
     * @param token  Access token authorizing certificate issuance
     * @param cNonce Nonce value provided by issuer to be included in proof of holder's binding
     */
    data class ProofRequired(
        override val token: IssuanceAccessToken,
        val cNonce: CNonce,
    ) : AuthorizedRequest
}

sealed interface SubmittedRequest {

    data class Success(
        val response: CredentialIssuanceResponse,
    ) : SubmittedRequest

    sealed interface Errored : SubmittedRequest

    data class Failed(
        val error: CredentialIssuanceError,
    ) : Errored

    class InvalidProof(
        val cNonce: CNonce,
        val errorDescription: String? = null,
    ) : Errored
}

interface AuthorizeIssuance {

    /*** Authorized Code Flow transitions ***/
    suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialMetadata>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested>

    suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: IssuanceAuthorization.AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved

    suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest>

    /*** Pre-Authorized Code Flow ***/
    suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialMetadata>,
        authorizationCode: IssuanceAuthorization.PreAuthorizationCode,
    ): Result<AuthorizedRequest>
}

interface RequestIssuance {
    suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest>

    suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        proof: Proof,
    ): Result<SubmittedRequest>

    suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
    ): Result<SubmittedRequest>

    suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, Proof>>,
    ): Result<SubmittedRequest>

    suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired
}

interface Issuer : AuthorizeIssuance, RequestIssuance {

    companion object {
        fun make(
            authorizer: IssuanceAuthorizer,
            requester: IssuanceRequester,
        ): Issuer =
            DefaultIssuer(authorizer, requester)

        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            issuerMetadata: CredentialIssuerMetadata,
            config: WalletOpenId4VCIConfig,
        ): Issuer =
            DefaultIssuer(
                IssuanceAuthorizer.ktor(
                    authorizationServerMetadata = authorizationServerMetadata,
                    config = config,
                ),
                IssuanceRequester.ktor(
                    issuerMetadata = issuerMetadata,
                ),
            )
    }
}

/**
 * Errors that can happen in the process of issuance process
 */
sealed interface CredentialIssuanceError {

    /**
     * Failure when placing Pushed Authorization Request to Authorization Server
     */
    data class PushedAuthorizationRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError

    /**
     * Failure when requesting access token from Authorization Server
     */
    data class AccessTokenRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError

    /**
     * Failure when creating an issuance request
     */
    data class InvalidIssuanceRequest(
        val message: String,
    ) : CredentialIssuanceError

    /**
     * Issuer rejected issuance request because no c_nonce was provided along with the proof. A fresh c_nonce is provided by issuer.
     */
    data class InvalidProof(
        val cNonce: String,
        val cNonceExpiresIn: Long? = 5,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError

    /**
     * Invalid access token passed to issuance server
     */
    object InvalidToken : CredentialIssuanceError
    object InvalidTransactionId : CredentialIssuanceError
    object UnsupportedCredentialType : CredentialIssuanceError
    object UnsupportedCredentialFormat : CredentialIssuanceError
    object InvalidEncryptionParameters : CredentialIssuanceError
    object IssuerDoesNotSupportBatchIssuance : CredentialIssuanceError

    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError

    data class ResponseUnparsable(val error: String) : CredentialIssuanceError
}

/**
 * Convert Error to throwable
 */
fun CredentialIssuanceError.asException() = CredentialIssuanceException(this)

fun CredentialIssuanceError.raise(): Nothing = throw CredentialIssuanceException(this)

/**
 * Exception denoting that a [CredentialIssuanceError] error happened in the process of a certificate issuance
 */
data class CredentialIssuanceException(val error: CredentialIssuanceError) : RuntimeException()
