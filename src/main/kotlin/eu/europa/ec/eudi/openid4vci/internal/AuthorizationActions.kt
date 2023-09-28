/*
 *
 *  * Copyright (c) 2023 European Commission
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.oauth2.sdk.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import eu.europa.ec.eudi.openid4vci.HttpFormPost
import eu.europa.ec.eudi.openid4vci.PKCEVerifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.util.*


sealed interface PushedAuthorizationRequestResponse {

    @Serializable
    data class Success(
        @SerialName("request_uri") val requestURI: String,
        @SerialName("expires_in") val expiresIn: Long = 5,
    ) : PushedAuthorizationRequestResponse

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String?,
    ) : PushedAuthorizationRequestResponse

}

sealed interface AccessTokenRequestResponse {

    @Serializable
    data class Success(
        @SerialName("access_token") val accessToken: String,
        @SerialName("expires_in") val expiresIn: Long,
        @SerialName("scope") val scope: List<String>,
        // ?? refreshToken, tokenType ??
    ) : AccessTokenRequestResponse

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String?,
    ) : AccessTokenRequestResponse

}

object AuthorizationActions {

    private const val ENDPOINT_AS_PAR = "/as/par"
    private const val ENDPOINT_AS_AUTHORIZE = "/authorize"
    private const val ENDPOINT_AS_TOKEN = "/token"
    suspend fun submitPushedAuthorizationRequest(
        authorizationServerUrl: URL,
        scopes: List<String>,
        postPar: HttpFormPost<PushedAuthorizationRequestResponse>
    ): Result<Pair<PKCEVerifier, URL>> = runCatching {

        val parEndpoint = URI.create(authorizationServerUrl.toString() + ENDPOINT_AS_PAR)
        val clientID = ClientID("123") // TODO: Get from config?
        val codeVerifier = CodeVerifier()

        val authzRequest: AuthorizationRequest = with(
            AuthorizationRequest.Builder(
                ResponseType("code"), clientID
            )
        ) {
            redirectionURI(URI.create("https://example.com/cb")) // TODO: Get from config?
            codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            scope(Scope(*scopes.toTypedArray()))
            build()
        }

        val clientSecret = Secret("chele3faiYieNg4taoy8ingai3eili3b") // TODO: Get from config?
        val clientAuth: ClientAuthentication = ClientSecretBasic(clientID, clientSecret) // TODO: Get from config?

        val pushedAuthorizationRequest = PushedAuthorizationRequest(parEndpoint, clientAuth, authzRequest)

        val response = postPar.post(parEndpoint.toURL(), pushedAuthorizationRequest.asFormPostParams())

        when (response) {
            is PushedAuthorizationRequestResponse.Success ->  response.toParResult(authorizationServerUrl, clientID, codeVerifier, CodeChallengeMethod.S256)
            is PushedAuthorizationRequestResponse.Failure ->  error("Failed in par with error: ${response.error} and error description: ${response.errorDescription}")
        }
    }

    suspend fun accessTokenAuthFlow(
        authorizationServerUrl: URL,
        authorizationCode: String,
        codeVerifier: String,
        getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
    ): Result<String> = runCatching {

//        val code = AuthorizationCode(authorizationCode)
//        val callback = URI("https://example.com/cb") // TODO: Get from config?
//        val codeGrant = AuthorizationCodeGrant(code, callback)
//        val clientID = ClientID("123") // TODO: Get from config?
//        val clientSecret = Secret("secret") // TODO: Get from config?
//        val clientAuth = ClientSecretBasic(clientID, clientSecret)
//        val tokenEndpoint = URI.create(authorizationServerUrl.toString() + ENDPOINT_AS_TOKEN)
//        val customParams = Collections.unmodifiableMap(mapOf("code_verifier" to listOf(codeVerifier)))
//        val tokenRequest = TokenRequest(tokenEndpoint, clientAuth, codeGrant, Scope(), null, customParams)
//        val response = getAccessToken.post(tokenEndpoint.toURL(), tokenRequest.asFormPostParams())

        val params = mapOf(
            "grant_type" to "authorization_code",
            "code" to authorizationCode,
            "redirect_uri" to "https://example.com/cb",  // TODO: Get from config?
            "client_id" to "123", // TODO: Get from config?
            "code_verifier" to codeVerifier
        )
        val tokenEndpoint = URL(authorizationServerUrl.toString() + ENDPOINT_AS_TOKEN)
        val response = getAccessToken.post(tokenEndpoint, params)

        when(response) {
            is AccessTokenRequestResponse.Success -> response.accessToken
            is AccessTokenRequestResponse.Failure -> error("Failed in par with error: ${response.error} and error description: ${response.errorDescription}")
        }
    }

    suspend fun accessTokenPreAuthFlow(
        authorizationServerUrl: URL?,
        preAuthorizedCode: String,
        pin: String,
        getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
    ): Result<String> = runCatching {

        val params = mapOf(
            "grant_type" to "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code" to preAuthorizedCode,
            "user_pin" to pin,
        )
        val tokenEndpoint = URL(authorizationServerUrl.toString() + ENDPOINT_AS_TOKEN)
        val response = getAccessToken.post(tokenEndpoint, params)

        when(response) {
            is AccessTokenRequestResponse.Success -> response.accessToken
            is AccessTokenRequestResponse.Failure -> error("Failed in par with error: ${response.error} and error description: ${response.errorDescription}")
        }
    }


    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        this.authorizationRequest.toParameters()
            .map { it.key to it.value.get(0) }
            .toMap()


    private fun PushedAuthorizationRequestResponse.Success.toParResult(
        authorizationServerUrl: URL,
        clientID: ClientID,
        verifier: CodeVerifier,
        verifierMethod: CodeChallengeMethod,
    ): Pair<PKCEVerifier, URL> {
        val authorizeRequestUrl = authorizationServerUrl.toString() + ENDPOINT_AS_AUTHORIZE +
                "?client_id=" + clientID.value +
                "&request_uri=" + URLEncoder.encode(this.requestURI, "UTF-8")
        return Pair(
             PKCEVerifier(verifier.value, verifierMethod.toString()),
             URL(authorizeRequestUrl )
        )
    }

}
