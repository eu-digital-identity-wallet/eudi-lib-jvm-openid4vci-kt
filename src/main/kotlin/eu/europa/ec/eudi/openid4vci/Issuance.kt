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

import eu.europa.ec.eudi.openid4vci.internal.formats.ClaimSet

/**
 * Holds a https [java.net.URL] to be used at the second step of PAR flow for retrieving the authorization code.
 * Contains the 'request_uri' retrieved from the post to PAR endpoint of authorization server and the client_id.
 */
class AuthorizationUrl private constructor(val url: HttpsUrl) {

    override fun toString(): String = url.toString()

    companion object {
        const val PARAM_CLIENT_ID = "client_id"
        const val PARAM_REQUEST_URI = "request_uri"
        const val PARAM_STATE = "state"
        operator fun invoke(url: String): AuthorizationUrl {
            val httpsUrl = HttpsUrl(url).getOrThrow()
            val query = requireNotNull(httpsUrl.value.query) { "URL must contain query parameter" }
            require(query.contains("$PARAM_CLIENT_ID=")) { "URL must contain client_id query parameter" }
            require(query.contains("$PARAM_REQUEST_URI=")) { "URL must contain request_uri query parameter" }
            return AuthorizationUrl(httpsUrl)
        }
    }
}

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
        val getAuthorizationCodeURL: AuthorizationUrl,
        val pkceVerifier: PKCEVerifier,
    )

    /**
     * State denoting that caller has followed the [ParRequested.getAuthorizationCodeURL] URL and response received
     * from authorization server and processed successfully.
     */
    data class AuthorizationCodeRetrieved(
        val authorizationCode: AuthorizationCode,
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
    val accessToken: AccessToken

    /**
     * Issuer authorized issuance
     *
     * @param accessToken Access token authorizing credential issuance
     */
    data class NoProofRequired(
        override val accessToken: AccessToken,
    ) : AuthorizedRequest

    /**
     * Issuer authorized issuance and requires the provision of proof of holder's binding to be provided
     * along with the request
     *
     * @param accessToken  Access token authorizing certificate issuance
     * @param cNonce Nonce value provided by issuer to be included in proof of holder's binding
     */
    data class ProofRequired(
        override val accessToken: AccessToken,
        val cNonce: CNonce,
    ) : AuthorizedRequest

    companion object {
        operator fun invoke(accessToken: AccessToken, cNonce: CNonce?): AuthorizedRequest =
            if (cNonce != null) ProofRequired(accessToken, cNonce)
            else NoProofRequired(accessToken)
    }
}

/**
 * The result of a request for issuance
 */
sealed interface IssuedCredential {

    /**
     * Credential was issued from server and the result is returned inline.
     *
     * @param format The format of the issued credential
     * @param credential The issued credential
     */
    data class Issued(
        val format: String,
        val credential: String,
    ) : IssuedCredential

    /**
     * Credential could not be issued immediately. An identifier is returned from server to be used later on
     * to request the credential from issuer's Deferred Credential Endpoint.
     *
     * @param transactionId  A string identifying a Deferred Issuance transaction.
     */
    data class Deferred(
        val transactionId: TransactionId,
    ) : IssuedCredential
}

/**
 * Sealed hierarchy of states describing the state of an issuance request submitted to a credential issuer.
 */
sealed interface SubmittedRequest {

    /**
     * State that denotes the successful submission of an issuance request
     * @param credentials The outcome of the issuance request. If issuance request was a batch request it will contain
     *      the results of each individual issuance request. If it was a single issuance request list will contain only one result.
     * @param cNonce Nonce information sent back from issuance server.
     */
    data class Success(
        val credentials: List<IssuedCredential>,
        val cNonce: CNonce?,
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
     * @param credentials   List of credentials whose issuance needs to be authorized.
     * @param issuerState   Credential issuer state passed via a credential offer grant of type [Grants.AuthorizationCode].
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow">OpenId4VCI</a>
     * @return The new state of the request or error.
     */
    suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialIdentifier>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested>

    /**
     * Second step to authorize an issuance request using Authorized Code Flow (utilizing PAR).
     * After authorization code is retrieved from front-channel, the authorization code is passed
     * to transition request from [UnauthorizedRequest.ParRequested] state to state [UnauthorizedRequest.AuthorizationCodeRetrieved]
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     * @return The new state of the request.
     */
    suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
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
     * @return The new state of the request or error.
     */
    suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialIdentifier>,
        preAuthorizationCode: PreAuthorizationCode,
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
     *  @param credentialId   The identifier of the credential that will be requested.
     *  @param claimSet Optional parameter to specify the specific set of claims that are requested to be included in the
     *          credential to be issued.
     *  @return The new state of the request or error.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest>

    /**
     *  Requests the issuance of a single credential having an [AuthorizedRequest.ProofRequired] authorization. In this
     *  case caller must provide a binding key that will be used for generating a Proof of Possession that issuer expects.
     *
     *  @param credentialId   The identifier of the credential that will be requested.
     *  @param claimSet     Optional parameter to specify the specific set of claims that are requested to be included in the
     *          credential to be issued.
     *  @param bindingKey   Cryptographic material to be used from issuer to bind the issued credential to a holder.
     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,

    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.NoProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.

     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialIdentifier, ClaimSet?>>,
    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.ProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.
     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialIdentifier, ClaimSet?, BindingKey>>,
    ): Result<SubmittedRequest>

    /**
     * Special purpose operation to handle the case an 'invalid_proof' error response was received from issuer with
     * fresh c_nonce provided to be used with a request retry.
     *
     * @param cNonce    The c_nonce provided from issuer along with the 'invalid_proof' error code.
     * @return The new state of the request.
     */
    suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired
}

sealed interface DeferredCredentialQueryOutcome {

    data class Issued(val credential: IssuedCredential.Issued) : DeferredCredentialQueryOutcome

    data class IssuancePending(
        val interval: Long? = null,
    ) : DeferredCredentialQueryOutcome

    data class Errored(
        val error: String,
        val errorDescription: String? = null,
    ) : DeferredCredentialQueryOutcome
}

/**
 * An interface for submitting a deferred credential issuance request.
 */
fun interface QueryForDeferredCredential {

    /**
     * Given an authorized request submits a deferred credential request for an identifier of a Deferred Issuance transaction.
     *
     * @param deferredCredential The identifier of a Deferred Issuance transaction.
     * @return The result of the submission.
     */
    suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<DeferredCredentialQueryOutcome>
}
