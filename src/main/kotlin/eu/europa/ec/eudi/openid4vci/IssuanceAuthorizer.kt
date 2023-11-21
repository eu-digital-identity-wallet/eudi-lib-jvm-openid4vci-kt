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

import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceAuthorizer
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorIssuanceAuthorizer
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Sealed hierarchy of possible responses to a Pushed Authorization Request.
 */
sealed interface PushedAuthorizationRequestResponse {

    /**
     * Successful request submission.
     *
     * @param requestURI A unique identifier of the authorization request.
     * @param expiresIn Time to live of the authorization request.
     */
    @Serializable
    data class Success(
        @SerialName("request_uri") val requestURI: String,
        @SerialName("expires_in") val expiresIn: Long = 5,
    ) : PushedAuthorizationRequestResponse

    /**
     * Request failed
     *
     * @param error The error reported from authorization server.
     * @param errorDescription A description of the error.
     */
    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : PushedAuthorizationRequestResponse
}

/**
 * Sealed hierarchy of possible responses to an Access Token request.
 */
sealed interface AccessTokenRequestResponse {

    /**
     * Successful request submission.
     *
     * @param accessToken The access token.
     * @param expiresIn Token time to live.
     * @param cNonce    c_nonce returned from token endpoint.
     * @param cNonceExpiresIn c_nonce time to live.
     */
    @Serializable
    data class Success(
        @SerialName("access_token") val accessToken: String,
        @SerialName("expires_in") val expiresIn: Long,
        @SerialName("c_nonce") val cNonce: String? = null,
        @SerialName("c_nonce_expires_in") val cNonceExpiresIn: Long? = null,
    ) : AccessTokenRequestResponse

    /**
     * Request failed
     *
     * @param error The error reported from authorization server.
     * @param errorDescription A description of the error.
     */
    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : AccessTokenRequestResponse
}

/**
 * Holds a https [java.net.URL] to be used at the second step of PAR flow for retrieving the authorization code.
 * Contains the 'request_uri' retrieved from the post to PAR endpoint of authorization server and the client_id.
 */
class AuthorizationUrl private constructor(val url: HttpsUrl) {
    override fun toString(): String {
        return url.toString()
    }

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
 * An interface for all interactions with an authorization server that protects the credential issuer.
 */
interface IssuanceAuthorizer {

    /**
     * Submit Pushed Authorization Request for authorizing an issuance request.
     *
     * @param scopes    The scopes of the authorization request.
     * @param state     The oauth2 specific 'state' request parameter.
     * @param issuerState   The state passed from credential issuer during the negotiation phase of the issuance.
     * @return The result of the request as a pair of the PKCE verifier used during request and the authorization code
     *      url that caller will need to follow in order to retrieve the authorization code.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9126.html">RFC9126</a>
     */
    suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, AuthorizationUrl>>

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * authorization code flow
     *
     * @param authorizationCode The authorization code generated from authorization server.
     * @param codeVerifier  The code verifier that was used when submitting the Pushed Authorization Request.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: String,
        codeVerifier: String,
    ): Result<Pair<String, CNonce?>>

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * pre-authorization code flow
     *
     * @param preAuthorizedCode The pre-authorization code.
     * @param pin  Extra pin code to be passed if specified as required in the credential offer.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenPreAuthFlow(
        preAuthorizedCode: String,
        pin: String?,
    ): Result<Pair<String, CNonce?>>

    companion object {

        /**
         * Factory method to create a default implementation of the [IssuanceAuthorizer] interface.
         *
         * @param authorizationServerMetadata Read-only authorization server metadata.
         * @param config Configuration object.
         * @param postPar An implementation of the http POST that submits the Pushed Authorization Request.
         * @param getAccessToken An implementation of the http POST that submits the request to get the access token.
         * @return A default implementation of the [IssuanceAuthorizer] interface.
         */
        fun make(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            config: OpenId4VCIConfig,
            postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
            getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
        ): IssuanceAuthorizer =
            DefaultIssuanceAuthorizer(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
                postPar = postPar,
                getAccessToken = getAccessToken,
            )

        /**
         * Factory method to create an [IssuanceAuthorizer] based on ktor.
         *
         * @param authorizationServerMetadata Read-only authorization server metadata
         * @param config Configuration object.
         * @param coroutineDispatcher A coroutine dispatcher.
         * @param ktorHttpClientFactory Factory of ktor http clients
         * @return An implementation of [IssuanceAuthorizer] based on ktor.
         */
        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            config: OpenId4VCIConfig,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            ktorHttpClientFactory: KtorHttpClientFactory = KtorIssuanceAuthorizer.HttpClientFactory,
        ): IssuanceAuthorizer =
            KtorIssuanceAuthorizer(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
                coroutineDispatcher = coroutineDispatcher,
                ktorHttpClientFactory = ktorHttpClientFactory,
            )
    }
}
