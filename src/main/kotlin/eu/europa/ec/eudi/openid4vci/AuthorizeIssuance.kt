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

import java.time.Instant

/**
 * State holding the authorization request as a URL to be passed to front-channel for retrieving an authorization code in an oAuth2
 * authorization code grant type flow.
 * @param authorizationCodeURL the authorization code URL
 * Contains all the parameters
 * @param pkceVerifier the PKCE verifier, which was used
 * for preparing the authorization request
 * @param state the state which was sent with the
 * authorization request
 */
data class AuthorizationRequestPrepared(
    val authorizationCodeURL: HttpsUrl,
    val pkceVerifier: PKCEVerifier,
    val state: String,
) : java.io.Serializable

/**
 * Sealed hierarchy of states describing an authorized issuance request. These states hold an access token issued by the
 * authorization server that protects the credential issuer.
 */
sealed interface AuthorizedRequest : java.io.Serializable {

    /**
     * Access token authorizing the request(s) to issue credential(s)
     */
    val accessToken: AccessToken
    val refreshToken: RefreshToken?
    val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?
    val timestamp: Instant

    fun isAccessTokenExpired(at: Instant): Boolean = accessToken.isExpired(timestamp, at)
    fun isRefreshTokenExpiredOrMissing(at: Instant): Boolean = refreshToken?.isExpired(timestamp, at) ?: true

    /**
     * In case an 'invalid_proof' error response was received from issuer with
     * fresh c_nonce
     *
     * @param cNonce    The c_nonce provided from issuer along the 'invalid_proof' error code.
     * @return The new state of the request.
     */
    fun withCNonce(cNonce: CNonce): ProofRequired =
        ProofRequired(accessToken, refreshToken, cNonce, credentialIdentifiers, timestamp)

    fun withRefreshedAccessToken(
        refreshedAccessToken: AccessToken,
        newRefreshToken: RefreshToken?,
        at: Instant,
    ): AuthorizedRequest =
        when (this) {
            is NoProofRequired -> copy(
                accessToken = refreshedAccessToken,
                refreshToken = newRefreshToken ?: refreshToken,
                timestamp = at,
            )

            is ProofRequired -> copy(
                accessToken = refreshedAccessToken,
                refreshToken = newRefreshToken ?: refreshToken,
                timestamp = at,
            )
        }

    /**
     * Issuer authorized issuance
     *
     * @param accessToken Access token authorizing credential issuance
     * @param refreshToken Refresh token to refresh the access token, if needed
     * @param credentialIdentifiers authorization details, if provided by the token endpoint
     * @param timestamp the point in time of the authorization (when tokens were issued)
     */
    data class NoProofRequired(
        override val accessToken: AccessToken,
        override val refreshToken: RefreshToken?,
        override val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
        override val timestamp: Instant,
    ) : AuthorizedRequest

    /**
     * Issuer authorized issuance and required the provision of proof of holder's binding to be provided
     * along with the request
     *
     * @param accessToken  Access token authorizing certificate issuance
     * @param refreshToken Refresh token to refresh the access token, if needed
     * @param cNonce Nonce value provided by issuer to be included in proof of holder's binding
     * @param credentialIdentifiers authorization details, if provided by the token endpoint
     * @param timestamp the point in time of the authorization (when tokens were issued)
     */
    data class ProofRequired(
        override val accessToken: AccessToken,
        override val refreshToken: RefreshToken?,
        val cNonce: CNonce,
        override val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
        override val timestamp: Instant,
    ) : AuthorizedRequest
}

interface AuthorizeIssuance {

    /**
     * Initial step to authorize an issuance request using Authorized Code Flow.
     * If the specified authorization server supports PAR,
     * then this method executes the first step of PAR by pushing the authorization
     * request to authorization server's 'par endpoint'.
     * If PAR is not supported, then this method prepares the authorization request as a typical authorization code flow authorization
     * request with the request's elements as query parameters.
     * @param walletState an optional parameter that if provided will
     * be included in the authorization request. If it is not provided,
     * a random value will be used
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @return an HTTPS URL of the authorization request to be placed
     */
    suspend fun prepareAuthorizationRequest(walletState: String? = null): Result<AuthorizationRequestPrepared>

    /**
     * Using the access code retrieved after performing the authorization request prepared from a call to
     * [AuthorizeOfferIssuance.prepareAuthorizationRequest()], it posts a request to authorization server's token endpoint to
     * retrieve an access token. This step transitions state from [AuthorizationRequestPrepared] to an
     * [AuthorizedRequest] state
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     * @param serverState The state returned from authorization server via front-channel
     * @return an issuance request in authorized state
     */
    suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
    ): Result<AuthorizedRequest>

    /**
     * Action to authorize an issuance request using Pre-Authorized Code Flow.
     *
     * @param txCode   Optional parameter in case the credential offer specifies that a user provided pin is required for authorization
     * @return an issuance request in authorized state
     */
    suspend fun authorizeWithPreAuthorizationCode(txCode: String?): Result<AuthorizedRequest>
}
