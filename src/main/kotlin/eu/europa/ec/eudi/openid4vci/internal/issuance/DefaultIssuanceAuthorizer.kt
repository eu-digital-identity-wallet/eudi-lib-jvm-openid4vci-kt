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
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URI
import java.net.URLEncoder
import com.nimbusds.oauth2.sdk.Scope as NimbusOauth2Scope

/**
 * Default implementation of [IssuanceAuthorizer] interface.
 */
internal class DefaultIssuanceAuthorizer(
    val coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
    val config: OpenId4VCIConfig,
    val postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
    val getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
) : IssuanceAuthorizer {

    override suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, GetAuthorizationCodeURL>> = runCatching {
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
            scope(NimbusOauth2Scope(*scopes.map { it.value }.toTypedArray(), "openid"))
            state(State(state))
            issuerState?.let {
                customParameter("issuer_state", issuerState)
            }
            build()
        }

        val pushedAuthorizationRequest = PushedAuthorizationRequest(parEndpoint, authzRequest)

        val response =
            withContext(coroutineDispatcher) {
                postPar.post(parEndpoint.toURL(), pushedAuthorizationRequest.asFormPostParams())
            }

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
                    parameters.append(GetAuthorizationCodeURL.PARAM_CLIENT_ID, clientID.value)
                    parameters.append(GetAuthorizationCodeURL.PARAM_STATE, state)
                    parameters.append(
                        GetAuthorizationCodeURL.PARAM_REQUEST_URI,
                        requestURI,
                    )
                    build()
                }

            val getAuthorizationCodeURL = GetAuthorizationCodeURL(httpsUrl.toString())

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

    override suspend fun requestAccessTokenAuthFlow(
        authorizationCode: String,
        codeVerifier: String,
    ): Result<Pair<String, CNonce?>> = runCatching {
        val params = TokenEndpointForm.AuthCodeFlow.of(
            authorizationCode,
            config.authFlowRedirectionURI,
            config.clientId,
            codeVerifier,
        )

        val response =
            withContext(coroutineDispatcher) {
                getAccessToken.post(
                    authorizationServerMetadata.tokenEndpointURI.toURL(),
                    params,
                )
            }

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

    override suspend fun requestAccessTokenPreAuthFlow(
        preAuthorizedCode: String,
        pin: String?,
    ): Result<Pair<String, CNonce?>> = runCatching {
        val params = TokenEndpointForm.PreAuthCodeFlow.of(preAuthorizedCode, pin)
        val response = withContext(coroutineDispatcher) {
            getAccessToken.post(
                authorizationServerMetadata.tokenEndpointURI.toURL(),
                params,
            )
        }

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

    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        this.authorizationRequest.toParameters()
            .mapValues { (_, value) -> value[0] }
            .toMap()
}

sealed interface TokenEndpointForm {

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
