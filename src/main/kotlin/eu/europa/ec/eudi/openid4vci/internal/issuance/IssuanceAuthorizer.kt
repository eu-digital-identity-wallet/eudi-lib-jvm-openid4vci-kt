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

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.call.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URLEncoder

/**
 * Sealed hierarchy of possible responses to a Pushed Authorization Request.
 */
internal sealed interface PushedAuthorizationRequestResponse {

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
internal sealed interface AccessTokenRequestResponse {

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
 * Default implementation of [IssuanceAuthorizer] interface.
 */
internal class IssuanceAuthorizer(
    private val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val authorizationServerMetadata: CIAuthorizationServerMetadata,
    private val config: OpenId4VCIConfig,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

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
    ): Result<Pair<PKCEVerifier, AuthorizationUrl>> = runCatching {
        require(scopes.isNotEmpty()) { "No scopes provided. Cannot submit par with no scopes." }

        val parEndpoint = authorizationServerMetadata.pushedAuthorizationRequestEndpointURI
        val clientID = ClientID(config.clientId)
        val codeVerifier = CodeVerifier()

        val authzRequest: AuthorizationRequest = with(
            AuthorizationRequest.Builder(
                ResponseType("code"),
                clientID,
            ),
        ) {
            redirectionURI(config.authFlowRedirectionURI)
            codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            scope(com.nimbusds.oauth2.sdk.Scope(*scopes.map { it.value }.toTypedArray()))
            state(State(state))
            issuerState?.let {
                customParameter("issuer_state", issuerState)
            }
            build()
        }

        val pushedAuthorizationRequest = PushedAuthorizationRequest(parEndpoint, authzRequest)

        val response = pushAuthorizationRequest(parEndpoint, pushedAuthorizationRequest)

        response.toPair(clientID, codeVerifier, state)
    }

    private fun PushedAuthorizationRequestResponse.toPair(
        clientID: ClientID,
        codeVerifier: CodeVerifier,
        state: String,
    ) = when (this) {
        is PushedAuthorizationRequestResponse.Success -> {
            val httpsUrl =
                with(
                    URLBuilder(Url(authorizationServerMetadata.authorizationEndpointURI.toString())),
                ) {
                    parameters.append(AuthorizationUrl.PARAM_CLIENT_ID, clientID.value)
                    parameters.append(AuthorizationUrl.PARAM_STATE, state)
                    parameters.append(
                        AuthorizationUrl.PARAM_REQUEST_URI,
                        requestURI,
                    )
                    build()
                }

            val getAuthorizationCodeURL = AuthorizationUrl(httpsUrl.toString())

            Pair(
                PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString()),
                getAuthorizationCodeURL,
            )
        }

        is PushedAuthorizationRequestResponse.Failure ->
            throw CredentialIssuanceError.PushedAuthorizationRequestFailed(
                error,
                errorDescription,
            )
    }

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
    ): Result<Pair<String, CNonce?>> = runCatching {
        val params = TokenEndpointForm.AuthCodeFlow.of(
            authorizationCode,
            config.authFlowRedirectionURI,
            config.clientId,
            codeVerifier,
        )

        val response = requestAccessToken(params)

        when (response) {
            is AccessTokenRequestResponse.Success -> {
                val cnonce = response.cNonce?.let { CNonce(it, response.cNonceExpiresIn) }
                Pair(response.accessToken, cnonce)
            }

            is AccessTokenRequestResponse.Failure ->
                throw CredentialIssuanceError.AccessTokenRequestFailed(
                    response.error,
                    response.errorDescription,
                )
        }
    }

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
    ): Result<Pair<String, CNonce?>> = runCatching {
        val params = TokenEndpointForm.PreAuthCodeFlow.of(preAuthorizedCode, pin)
        val response = requestAccessToken(params)

        when (response) {
            is AccessTokenRequestResponse.Success -> {
                val cNonce = response.cNonce?.let { CNonce(it, response.cNonceExpiresIn) }
                Pair(response.accessToken, cNonce)
            }

            is AccessTokenRequestResponse.Failure ->
                throw CredentialIssuanceError.AccessTokenRequestFailed(
                    response.error,
                    response.errorDescription,
                )
        }
    }

    private suspend fun requestAccessToken(params: Map<String, String>): AccessTokenRequestResponse =
        withContext(coroutineDispatcher) {
            ktorHttpClientFactory().use { client ->
                val url = authorizationServerMetadata.tokenEndpointURI.toURL()
                val response = client.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        params.entries.forEach { (k, v) -> append(k, v) }
                    },
                )
                if (response.status.isSuccess()) response.body<AccessTokenRequestResponse.Success>()
                else response.body<AccessTokenRequestResponse.Failure>()
            }
        }


    private suspend fun pushAuthorizationRequest(
        parEndpoint: URI,
        pushedAuthorizationRequest: PushedAuthorizationRequest,
    ): PushedAuthorizationRequestResponse =
        withContext(coroutineDispatcher) {
            ktorHttpClientFactory().use { client ->
                val url = parEndpoint.toURL()
                val formParameters = pushedAuthorizationRequest.asFormPostParams()
                val response = client.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        formParameters.entries.forEach { (k, v) -> append(k, v) }
                    },
                )
                if (response.status.isSuccess()) response.body<PushedAuthorizationRequestResponse.Success>()
                else response.body<PushedAuthorizationRequestResponse.Failure>()

            }
        }

    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        this.authorizationRequest.toParameters()
            .mapValues { (_, value) -> value[0] }
            .toMap()


}

internal sealed interface TokenEndpointForm {

    class AuthCodeFlow : TokenEndpointForm {
        companion object {
            const val GRANT_TYPE_PARAM = "grant_type"
            const val GRANT_TYPE_PARAM_VALUE = "authorization_code"
            const val REDIRECT_URI_PARAM = "redirect_uri"
            const val CLIENT_ID_PARAM = "client_id"
            const val CODE_VERIFIER_PARAM = "code_verifier"
            const val AUTHORIZATION_CODE_PARAM = "code"

            fun of(
                authorizationCode: String,
                redirectionURI: URI,
                clientId: String,
                codeVerifier: String,
            ): Map<String, String> =
                mapOf(
                    GRANT_TYPE_PARAM to GRANT_TYPE_PARAM_VALUE,
                    AUTHORIZATION_CODE_PARAM to authorizationCode,
                    REDIRECT_URI_PARAM to redirectionURI.toString(),
                    CLIENT_ID_PARAM to clientId,
                    CODE_VERIFIER_PARAM to codeVerifier,
                )
        }
    }

    class PreAuthCodeFlow : TokenEndpointForm {
        companion object {
            const val GRANT_TYPE_PARAM = "grant_type"
            const val GRANT_TYPE_PARAM_VALUE = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            const val USER_PIN_PARAM = "user_pin"
            const val PRE_AUTHORIZED_CODE_PARAM = "pre_authorized_code"

            fun of(preAuthorizedCode: String, userPin: String?): Map<String, String> {
                return if (userPin != null) {
                    mapOf(
                        GRANT_TYPE_PARAM to URLEncoder.encode(GRANT_TYPE_PARAM_VALUE, "UTF-8"),
                        PRE_AUTHORIZED_CODE_PARAM to preAuthorizedCode,
                        USER_PIN_PARAM to userPin,
                    )
                } else {
                    mapOf(
                        GRANT_TYPE_PARAM to URLEncoder.encode(GRANT_TYPE_PARAM_VALUE, "UTF-8"),
                        PRE_AUTHORIZED_CODE_PARAM to preAuthorizedCode,
                    )
                }
            }
        }
    }
}