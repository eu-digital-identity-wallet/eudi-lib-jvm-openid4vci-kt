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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.oauth2.sdk.AuthorizationRequest
import com.nimbusds.oauth2.sdk.PushedAuthorizationRequest
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.id.State
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import com.nimbusds.oauth2.sdk.rar.AuthorizationType
import com.nimbusds.oauth2.sdk.rar.Location
import com.nimbusds.openid.connect.sdk.Prompt
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.AccessTokenRequestFailed
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.PushedAuthorizationRequestFailed
import eu.europa.ec.eudi.openid4vci.Grants.PreAuthorizedCode
import eu.europa.ec.eudi.openid4vci.internal.*
import io.ktor.client.call.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import com.nimbusds.oauth2.sdk.Scope as NimbusScope
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail as NimbusAuthorizationDetail

/**
 * Sealed hierarchy of possible responses to a Pushed Authorization Request.
 */
internal sealed interface PushedAuthorizationRequestResponseTO {

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
    ) : PushedAuthorizationRequestResponseTO

    /**
     * Request failed
     *
     * @param error The error reported from the authorization server.
     * @param errorDescription A description of the error.
     */
    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : PushedAuthorizationRequestResponseTO
}

/**
 * Sealed hierarchy of possible responses to an Access Token request.
 */
internal sealed interface TokenResponseTO {

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
        @SerialName("token_type") val tokenType: String? = null,
        @SerialName("access_token") val accessToken: String,
        @SerialName("refresh_token") val refreshToken: String? = null,
        @SerialName("expires_in") val expiresIn: Long? = null,
        @SerialName("c_nonce") val cNonce: String? = null,
        @SerialName("c_nonce_expires_in") val cNonceExpiresIn: Long? = null,
        @Serializable(with = GrantedAuthorizationDetailsSerializer::class)
        @SerialName(
            "authorization_details",
        ) val authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>? = null,
    ) : TokenResponseTO

    /**
     * Request failed
     *
     * @param error The error reported from the authorization server.
     * @param errorDescription A description of the error.
     */
    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : TokenResponseTO

    fun tokensOrFail(): TokenResponse =
        when (this) {
            is Success -> {
                TokenResponse(
                    accessToken = AccessToken(accessToken, DPoP.equals(other = tokenType, ignoreCase = true)),
                    refreshToken = refreshToken?.let { RefreshToken(it) },
                    cNonce = cNonce?.let { CNonce(it, cNonceExpiresIn) },
                    authorizationDetails = authorizationDetails ?: emptyMap(),
                )
            }

            is Failure -> throw AccessTokenRequestFailed(error, errorDescription)
        }
}

internal class AuthorizationServerClient(
    private val credentialIssuerId: CredentialIssuerId,
    private val authorizationServerMetadata: CIAuthorizationServerMetadata,
    private val config: OpenId4VCIConfig,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
    private val parUsage: ParUsage,
) {

    private val supportsPar: Boolean
        get() = authorizationServerMetadata.pushedAuthorizationRequestEndpointURI != null

    suspend fun submitParOrCreateAuthorizationRequestUrl(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> {
        val usePar = when (parUsage) {
            ParUsage.IfSupported -> supportsPar
            ParUsage.Never -> false
            ParUsage.Required -> {
                require(supportsPar) {
                    "PAR uses is required, yet authorization server doesn't advertise PAR endpoint"
                }
                true
            }
        }
        return if (usePar) {
            submitPushedAuthorizationRequest(scopes, credentialsConfigurationIds, state, issuerState)
        } else {
            authorizationRequestUrl(scopes, credentialsConfigurationIds, state, issuerState)
        }
    }

    /**
     * Submit Pushed Authorization Request for authorizing an issuance request.
     *
     * @param scopes    The scopes of the authorization request.
     * @param state     The oauth2 specific 'state' request parameter.
     * @param issuerState   The state passed from credential issuer during the negotiation phase of the issuance.
     * @return The result of the request as a pair of the PKCE verifier used during request and the authorization code
     *      url that caller will need to follow to retrieve the authorization code.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9126.html">RFC9126</a>
     */
    suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> = runCatching {
        require(scopes.isNotEmpty() || credentialsConfigurationIds.isNotEmpty()) {
            "No scopes or authorization details provided. Cannot submit par."
        }

        val parEndpoint = authorizationServerMetadata.pushedAuthorizationRequestEndpointURI
        checkNotNull(parEndpoint) { "PAR endpoint not advertised" }
        val clientID = ClientID(config.clientId)
        val codeVerifier = CodeVerifier()
        val pushedAuthorizationRequest = run {
            val request = AuthorizationRequest.Builder(ResponseType.CODE, clientID).apply {
                redirectionURI(config.authFlowRedirectionURI)
                codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                state(State(state))
                issuerState?.let { customParameter("issuer_state", issuerState) }
                if (scopes.isNotEmpty()) {
                    scope(NimbusScope(*scopes.map { it.value }.toTypedArray()))
                }
                if (credentialsConfigurationIds.isNotEmpty()) {
                    authorizationDetails(credentialsConfigurationIds.map(::toNimbus))
                }
                prompt(Prompt.Type.LOGIN)
            }.build()
            PushedAuthorizationRequest(parEndpoint, request)
        }
        val response = pushAuthorizationRequest(parEndpoint, pushedAuthorizationRequest)

        response.authorizationCodeUrlOrFail(clientID, codeVerifier, state)
    }

    fun authorizationRequestUrl(
        credentialsScopes: List<Scope>,
        credentialsAuthorizationDetails: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> = runCatching {
        require(credentialsScopes.isNotEmpty() || credentialsAuthorizationDetails.isNotEmpty()) {
            "No scopes or authorization details provided. Cannot prepare authorization request."
        }

        val clientID = ClientID(config.clientId)
        val codeVerifier = CodeVerifier()
        val authorizationRequest = AuthorizationRequest.Builder(ResponseType.CODE, clientID).apply {
            endpointURI(authorizationServerMetadata.authorizationEndpointURI)
            redirectionURI(config.authFlowRedirectionURI)
            codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            state(State(state))
            issuerState?.let { customParameter("issuer_state", issuerState) }
            if (credentialsScopes.isNotEmpty()) {
                scope(NimbusScope(*credentialsScopes.map { it.value }.toTypedArray()))
            }
            if (credentialsAuthorizationDetails.isNotEmpty()) {
                authorizationDetails(credentialsAuthorizationDetails.map(::toNimbus))
            }
            prompt(Prompt.Type.LOGIN)
        }.build()

        val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
        val url = HttpsUrl(authorizationRequest.toURI().toString()).getOrThrow()
        pkceVerifier to url
    }

    private fun PushedAuthorizationRequestResponseTO.authorizationCodeUrlOrFail(
        clientID: ClientID,
        codeVerifier: CodeVerifier,
        state: String,
    ): Pair<PKCEVerifier, HttpsUrl> = when (this) {
        is PushedAuthorizationRequestResponseTO.Success -> {
            val authorizationCodeUrl = run {
                val httpsUrl = URLBuilder(Url(authorizationServerMetadata.authorizationEndpointURI.toString())).apply {
                    parameters.append(AuthorizationEndpointParams.PARAM_CLIENT_ID, clientID.value)
                    parameters.append(AuthorizationEndpointParams.PARAM_STATE, state)
                    parameters.append(AuthorizationEndpointParams.PARAM_REQUEST_URI, requestURI)
                }.build()
                HttpsUrl(httpsUrl.toString()).getOrThrow()
            }
            val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
            pkceVerifier to authorizationCodeUrl
        }

        is PushedAuthorizationRequestResponseTO.Failure -> throw PushedAuthorizationRequestFailed(
            error,
            errorDescription,
        )
    }

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * authorization code flow
     *
     * @param authorizationCode The authorization code generated from authorization server.
     * @param pkceVerifier  The code verifier that was used when submitting the Pushed Authorization Request.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: AuthorizationCode,
        pkceVerifier: PKCEVerifier,
    ): Result<TokenResponse> = runCatching {
        val params = TokenEndpointForm.authCodeFlow(
            authorizationCode = authorizationCode,
            redirectionURI = config.authFlowRedirectionURI,
            clientId = config.clientId,
            pkceVerifier = pkceVerifier,
        )
        requestAccessToken(params).tokensOrFail()
    }

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * pre-authorization code flow
     *
     * @param preAuthorizedCode The pre-authorization code.
     * @param txCode  Extra transaction code to be passed if specified as required in the credential offer.
     * @return The result of the request as a pair of the access token and the optional c_nonce information returned
     *      from token endpoint.
     */
    suspend fun requestAccessTokenPreAuthFlow(
        preAuthorizedCode: PreAuthorizedCode,
        txCode: String?,
    ): Result<TokenResponse> = runCatching {
        val params = TokenEndpointForm.preAuthCodeFlow(
            clientId = config.clientId,
            preAuthorizedCode = preAuthorizedCode,
            txCode = txCode,
        )
        requestAccessToken(params).tokensOrFail()
    }

    private suspend fun requestAccessToken(
        params: Map<String, String>,
    ): TokenResponseTO =
        ktorHttpClientFactory().use { client ->
            val url = authorizationServerMetadata.tokenEndpointURI.toURL()
            val formParameters = Parameters.build {
                params.entries.forEach { (k, v) -> append(k, v) }
            }
            val response = client.submitForm(url.toString(), formParameters) {
                dPoPJwtFactory?.let { factory ->
                    dpop(factory, url, Htm.POST, accessToken = null, nonce = null)
                }
            }
            if (response.status.isSuccess()) response.body<TokenResponseTO.Success>()
            else response.body<TokenResponseTO.Failure>()
        }

    private suspend fun pushAuthorizationRequest(
        parEndpoint: URI,
        pushedAuthorizationRequest: PushedAuthorizationRequest,
    ): PushedAuthorizationRequestResponseTO = ktorHttpClientFactory().use { client ->
        val url = parEndpoint.toURL()
        val formParameters = pushedAuthorizationRequest.asFormPostParams()

        val response = client.submitForm(
            url = url.toString(),
            formParameters = Parameters.build {
                formParameters.entries.forEach { (k, v) -> append(k, v) }
            },
        )
        if (response.status.isSuccess()) response.body<PushedAuthorizationRequestResponseTO.Success>()
        else response.body<PushedAuthorizationRequestResponseTO.Failure>()
    }

    private fun toNimbus(
        credentialConfigurationId: CredentialConfigurationIdentifier,
    ): AuthorizationDetail =
        with(NimbusAuthorizationDetail.Builder(AuthorizationType(OPENID_CREDENTIAL))) {
            if (credentialIssuerId.toString() != authorizationServerMetadata.issuer.toString()) {
                val locations = listOf(Location(credentialIssuerId.value.value.toURI()))
                locations(locations)
            }
            field("credential_configuration_id", credentialConfigurationId.value)
        }.build()

    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        authorizationRequest.toParameters().mapValues { (_, value) -> value[0] }.toMap()
}

private const val OPENID_CREDENTIAL = "openid_credential"

private object AuthorizationEndpointParams {
    const val PARAM_CLIENT_ID = "client_id"
    const val PARAM_REQUEST_URI = "request_uri"
    const val PARAM_STATE = "state"
}

internal object TokenEndpointForm {
    const val AUTHORIZATION_CODE_GRANT = "authorization_code"
    const val PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    const val REDIRECT_URI_PARAM = "redirect_uri"
    const val CODE_VERIFIER_PARAM = "code_verifier"
    const val AUTHORIZATION_CODE_PARAM = "code"
    const val CLIENT_ID_PARAM = "client_id"
    const val GRANT_TYPE_PARAM = "grant_type"
    const val TX_CODE_PARAM = "tx_code"
    const val PRE_AUTHORIZED_CODE_PARAM = "pre-authorized_code"

    fun authCodeFlow(
        clientId: String,
        authorizationCode: AuthorizationCode,
        redirectionURI: URI,
        pkceVerifier: PKCEVerifier,
    ): Map<String, String> = buildMap<String, String> {
        put(CLIENT_ID_PARAM, clientId)
        put(GRANT_TYPE_PARAM, AUTHORIZATION_CODE_GRANT)
        put(AUTHORIZATION_CODE_PARAM, authorizationCode.code)
        put(REDIRECT_URI_PARAM, redirectionURI.toString())
        put(CODE_VERIFIER_PARAM, pkceVerifier.codeVerifier)
    }.toMap()

    fun preAuthCodeFlow(
        clientId: String,
        preAuthorizedCode: PreAuthorizedCode,
        txCode: String?,
    ): Map<String, String> =
        buildMap {
            put(CLIENT_ID_PARAM, clientId)
            put(GRANT_TYPE_PARAM, PRE_AUTHORIZED_CODE_GRANT)
            put(PRE_AUTHORIZED_CODE_PARAM, preAuthorizedCode.preAuthorizedCode)
            txCode?.let { put(TX_CODE_PARAM, it) }
        }.toMap()
}
