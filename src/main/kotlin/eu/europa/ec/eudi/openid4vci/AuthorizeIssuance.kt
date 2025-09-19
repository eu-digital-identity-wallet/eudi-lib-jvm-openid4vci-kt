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
 * @param identifiersSentAsAuthDetails The list of the offer's [CredentialConfigurationIdentifier]s that are or will be communicated to
 * authorization server as detailed authorizations, part of a Rich Authorization Request.
 */
data class AuthorizationRequestPrepared(
    val authorizationCodeURL: HttpsUrl,
    val pkceVerifier: PKCEVerifier,
    val state: String,
    val identifiersSentAsAuthDetails: List<CredentialConfigurationIdentifier>,
    val dpopNonce: Nonce?,
) : java.io.Serializable

enum class Grant : java.io.Serializable {
    AuthorizationCode,
    PreAuthorizedCodeGrant,
}

/**
 * Sealed hierarchy of states describing an authorized issuance request. These states hold an access token issued by the
 * authorization server that protects the credential issuer.
 *
 * @param accessToken Access token authorizing the request(s) to issue credential(s)
 * @param refreshToken Refresh token to refresh the access token, if needed
 * @param credentialIdentifiers authorization details, if provided by the token endpoint
 * @param authorizationServerDpopNonce Nonce value for DPoP provided by the Authorization Server
 * @param timestamp the point in time of the authorization (when tokens were issued)
 * @param resourceServerDpopNonce Nonce value for DPoP provided by the Resource Server
 * @param grant The Grant through which the authorization was obtained
 */
data class AuthorizedRequest(
    val accessToken: AccessToken,
    val refreshToken: RefreshToken?,
    val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
    val timestamp: Instant,
    val authorizationServerDpopNonce: Nonce?,
    val resourceServerDpopNonce: Nonce?,
    val grant: Grant,
) : java.io.Serializable {

    fun isAccessTokenExpired(at: Instant): Boolean = accessToken.isExpired(timestamp, at)

    fun withRefreshedAccessToken(
        refreshedAccessToken: AccessToken,
        newRefreshToken: RefreshToken?,
        at: Instant,
        newAuthorizationServerDpopNonce: Nonce?,
    ): AuthorizedRequest =
        copy(
            accessToken = refreshedAccessToken,
            refreshToken = newRefreshToken ?: refreshToken,
            timestamp = at,
            authorizationServerDpopNonce = newAuthorizationServerDpopNonce,
        )

    fun withResourceServerDpopNonce(newResourceServerDpopNonce: Nonce?): AuthorizedRequest = copy(
        resourceServerDpopNonce = newResourceServerDpopNonce,
    )
}

sealed interface AccessTokenOption {

    data object AsRequested : AccessTokenOption

    data class Limited(val filter: (CredentialConfigurationIdentifier) -> Boolean) : AccessTokenOption
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
     * [AuthorizedRequest] state.
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     * @param serverState The state returned from authorization server via front-channel
     * @param authDetailsOption Defines if upon access token request extra authorization details will be set to fine grain the
     * scope of the access token.
     * @return an issuance request in authorized state
     */
    suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
        authDetailsOption: AccessTokenOption = AccessTokenOption.AsRequested,
    ): Result<AuthorizedRequest>

    /**
     * Action to authorize an issuance request using Pre-Authorized Code Flow.
     *
     * @param txCode   Optional parameter in case the credential offer specifies that a user provided pin is required for authorization
     * @param authDetailsOption An option to include authorization_details in the request or not
     * @return an issuance request in authorized state
     */
    suspend fun authorizeWithPreAuthorizationCode(
        txCode: String?,
        authDetailsOption: AccessTokenOption = AccessTokenOption.AsRequested,
    ): Result<AuthorizedRequest>
}
