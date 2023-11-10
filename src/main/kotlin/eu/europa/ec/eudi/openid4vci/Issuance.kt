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

/**
 * Sealed hierarchy of states that denote the individual steps that need to be taken in order to authorize a request for issuance
 * using the Authorized Code Flow, utilizing Pushed Authorization Request and PKCE.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9126.html">RFC9126</a>
 */
sealed interface UnauthorizedRequest {

    /**
     * State denoting that the pushed authorization request has been placed successfully and response processed
     */
    data class ParRequested(
        val getAuthorizationCodeURL: GetAuthorizationCodeURL,
        val pkceVerifier: PKCEVerifier,
        val state: String,
    )

    /**
     * State denoting that caller has followed the [ParRequested.getAuthorizationCodeURL] URL and response received
     * from authorization server and processed successfully.
     */
    data class AuthorizationCodeRetrieved(
        val authorizationCode: IssuanceAuthorization.AuthorizationCode,
        val pkceVerifier: PKCEVerifier,
    )
}

/**
 * Sealed hierarchy of states describing an authorized issuance request. These states hold an access token issued by the
 * authorization server that protects the credentials issuer.
 */
sealed interface AuthorizedRequest {

    /**
     * Access token authorizing the request(s) to issue credential(s)
     */
    val token: IssuanceAccessToken

    /**
     * Issuer authorized issuance
     *
     * @param token Access token authorizing credential issuance
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

/**
 * Sealed hierarchy of states describing the state of an issuance request submitted to a credential issuer.
 */
sealed interface SubmittedRequest {

    /**
     * State that denotes the successful submission of an issuance request
     *
     * @param response The response from credential issuer
     */
    data class Success(
        val response: CredentialIssuanceResponse,
    ) : SubmittedRequest

    /**
     * Sealed hierarchy of erroneous credential issuance request
     */
    sealed interface Errored : SubmittedRequest

    /**
     * State that denotes that the credential issuance request has failed
     *
     * @param error The error that caused the failure of the request
     */
    data class Failed(
        val error: CredentialIssuanceError,
    ) : Errored

    /**
     * State denoting a special case of request failure. Issuer has responded that the proof of possession provided in
     * the request was invalid. Along with the error, issuer responds with a new c_nonce to be used in the request retry.
     *
     * @param cNonce The c_nonce provided from issuer along with the error
     * @param errorDescription Description of the error that caused the failure
     */
    class InvalidProof(
        val cNonce: CNonce,
        val errorDescription: String? = null,
    ) : Errored
}

/**
 * An interface for authorizing a credential issuance request. Contains all the operation available to transition an [UnauthorizedRequest]
 * to an [AuthorizedRequest]
 */
interface AuthorizeIssuance {

    /**
     * Initial step to authorize an issuance request using Authorized Code Flow (utilizing PAR).
     * Pushes the authorization request to authorization server's 'par endpoint'. Result of this transition is the
     * [UnauthorizedRequest.ParRequested] state
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow">OpenId4VCI</a>
     */
    suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialMetadata>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested>

    /**
     * Second step to authorize an issuance request using Authorized Code Flow (utilizing PAR).
     * After authorization code is retrieved from front-channel, the authorization code is passed
     * to transition request from [UnauthorizedRequest.ParRequested] state to state [UnauthorizedRequest.AuthorizationCodeRetrieved]
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     */
    suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: IssuanceAuthorization.AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved

    /**
     * Last step to authorize an issuance request using Authorized Code Flow (utilizing PAR).
     * Using the access code retrieved from previous step, posts a request to authorization server's token endpoint to
     * retrieve an access token. This step transitions state from [UnauthorizedRequest.AuthorizationCodeRetrieved] to an
     * [AuthorizedRequest] state
     */
    suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest>

    /**
     * Action to authorize an issuance request using Pre-Authorized Code Flow.
     *
     * @param credentials   Metadata of the credentials whose issuance needs to be authorized.
     * @param preAuthorizationCode  The pre-authorization code retrieved from a [CredentialOffer]
     */
    suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialMetadata>,
        preAuthorizationCode: IssuanceAuthorization.PreAuthorizationCode,
    ): Result<AuthorizedRequest>
}

/**
 * An interface for submitting a credential issuance request. Contains all the operation available to transition an [AuthorizedRequest]
 * to a [SubmittedRequest]
 */
interface RequestIssuance {

    /**
     *  Requests the issuance of a single credential having an [AuthorizedRequest.NoProofRequired] authorization.
     *
     *  @param credentialMetadata   The metadata specifying the credential that will be requested.
     *  @param claimSet Optional parameter to specify the specific set of claims that are requested to be included in the
     *          credential to be issued.
     *  @param responseEncryptionSpec   Optional parameter that expresses the expected encryption of an issuer's
     *          encrypted response, if issuer enforces encrypted responses.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest>

    /**
     *  Requests the issuance of a single credential having an [AuthorizedRequest.ProofRequired] authorization. In this
     *  case caller must provide a binding key that will be used for generating a Proof of Possession that issuer expects.
     *
     *  @param credentialMetadata   The metadata specifying the credentials that will be requested.
     *  @param claimSet     Optional parameter to specify the specific set of claims that are requested to be included in the
     *          credential to be issued.
     *  @param bindingKey   Cryptographic material to be used from issuer to bind the issued credential to a holder.
     *  @param responseEncryptionSpec   Optional parameter that expresses the expected encryption of an issuer's
     *          encrypted response, if issuer enforces encrypted responses.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.NoProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.
     *  @param responseEncryptionSpec   Optional parameter that expresses the expected encryption of an issuer's
     *          encrypted response, if issuer enforces encrypted responses.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.ProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.
     *  @param responseEncryptionSpec   Optional parameter that expresses the expected encryption of an issuer's
     *          encrypted response, if issuer enforces encrypted responses.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, BindingKey>>,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest>

    /**
     * Special purpose operation to handle the case an 'invalid_proof' error response was received from issuer with
     * fresh c_nonce provided to be used with a request retry.
     *
     * @param cNonce    The c_nonce provided from issuer along with the 'invalid_proof' error code.
     */
    suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired
}

/**
 * Aggregation interface providing all functionality required for performing a credential issuance request (batch or single)
 * Provides factory methods for creating implementations of this interface.
 */
interface Issuer : AuthorizeIssuance, RequestIssuance {

    companion object {

        /**
         * Factory method for creating an issuer component.
         *
         * @param authorizer    An [IssuanceAuthorization] component responsible for all interactions with authorization server to authorize
         *      a request for credential(s) issuance.
         * @param requester     An [IssuanceRequester] component responsible for all interactions with credential issuer for submitting
         *      credential issuance requests.
         */
        fun make(
            authorizer: IssuanceAuthorizer,
            requester: IssuanceRequester,
        ): Issuer =
            DefaultIssuer(authorizer, requester)

        /**
         * Factory method to create an [Issuer] based on ktor
         *
         * @param authorizationServerMetadata   The authorization server metadata required from the underlying [IssuanceAuthorizer] component.
         * @param issuerMetadata    The credential issuer metadata required from the underlying [IssuanceRequester] component.
         * @param config    Configuration object
         */
        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            issuerMetadata: CredentialIssuerMetadata,
            config: OpenId4VCIConfig,
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
sealed class CredentialIssuanceError(message: String) : Throwable(message) {

    /**
     * Failure when placing Pushed Authorization Request to Authorization Server
     */
    data class PushedAuthorizationRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when requesting access token from Authorization Server
     */
    data class AccessTokenRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when creating an issuance request
     */
    class InvalidIssuanceRequest(
        message: String,
    ) : CredentialIssuanceError(message)

    /**
     * Issuer rejected the issuance request because no c_nonce was provided along with the proof.
     * A fresh c_nonce is provided by the issuer.
     */
    data class InvalidProof(
        val cNonce: String,
        val cNonceExpiresIn: Long? = 5,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("Invalid Proof")

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError("DeferredCredentialIssuancePending")

    /**
     * Invalid access token passed to issuance server
     */
    data object InvalidToken : CredentialIssuanceError("InvalidToken") {
        private fun readResolve(): Any = InvalidToken
    }

    /**
     * Invalid transaction id passed to issuance server in the context of deferred credential requests
     */
    data object InvalidTransactionId : CredentialIssuanceError("InvalidTransactionId") {
        private fun readResolve(): Any = InvalidTransactionId
    }

    /**
     * Invalid credential type requested to issuance server
     */
    data object UnsupportedCredentialType : CredentialIssuanceError("UnsupportedCredentialType") {
        private fun readResolve(): Any = UnsupportedCredentialType
    }

    /**
     * Un-supported credential type requested to issuance server
     */
    data object UnsupportedCredentialFormat : CredentialIssuanceError("UnsupportedCredentialFormat") {
        private fun readResolve(): Any = UnsupportedCredentialFormat
    }

    /**
     * Invalid encryption parameters passed to issuance server
     */
    data object InvalidEncryptionParameters : CredentialIssuanceError("InvalidEncryptionParameters") {
        private fun readResolve(): Any = InvalidEncryptionParameters
    }

    /**
     * Issuance server does not support batch credential requests
     */
    data object IssuerDoesNotSupportBatchIssuance : CredentialIssuanceError("IssuerDoesNotSupportBatchIssuance") {
        private fun readResolve(): Any = IssuerDoesNotSupportBatchIssuance
    }

    /**
     * Generic failure during issuance request
     */
    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Issuance server response is un-parsable
     */
    data class ResponseUnparsable(val error: String) : CredentialIssuanceError("ResponseUnparsable")

    /**
     * Sealed hierarchy of errors related to proof generation
     */
    sealed class ProofGenerationError(message: String) : CredentialIssuanceError(message) {

        /**
         * Binding method specified is not supported from issuer server
         */
        data object BindingMethodNotSupported : ProofGenerationError("BindingMethodNotSupported") {
            private fun readResolve(): Any = BindingMethodNotSupported
        }

        /**
         * Cryptographic binding method is not supported from the issuance server for a specific credential
         */
        data object CryptographicBindingMethodNotSupported : ProofGenerationError("CryptographicBindingMethodNotSupported") {
            private fun readResolve(): Any = CryptographicBindingMethodNotSupported
        }

        /**
         * Proof type provided for specific credential is not supported from issuance server
         */
        data object ProofTypeNotSupported : ProofGenerationError("ProofTypeNotSupported") {
            private fun readResolve(): Any = ProofTypeNotSupported
        }
    }

    /**
     * Sealed hierarchy of errors related to validation of encryption parameters passed along with the issuance request.
     */
    sealed class ResponseEncryptionError(message: String) : CredentialIssuanceError(message) {

        /**
         * Issuance server does not support encrypted responses
         */
        data object IssuerDoesNotSupportEncryptedResponses :
            ProofGenerationError("IssuerDoesNotSupportEncryptedResponses") {
            private fun readResolve(): Any = IssuerDoesNotSupportEncryptedResponses
        }

        /**
         * Response encryption algorithm specified in request is not supported from issuance server
         */
        data object ResponseEncryptionAlgorithmNotSupportedByIssuer :
            ProofGenerationError("ResponseEncryptionAlgorithmNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionAlgorithmNotSupportedByIssuer
        }

        /**
         * Response encryption method specified in request is not supported from issuance server
         */
        data object ResponseEncryptionMethodNotSupportedByIssuer :
            ProofGenerationError("ResponseEncryptionMethodNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionMethodNotSupportedByIssuer
        }

        /**
         * Issuer enforces encrypted responses but encryption parameters not provided in request
         */
        data object IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided :
            ProofGenerationError("IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided") {
            private fun readResolve(): Any = IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
        }
    }
}
