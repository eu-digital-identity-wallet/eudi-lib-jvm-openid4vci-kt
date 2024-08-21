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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.PushedAuthorizationRequestFailed
import io.ktor.client.call.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
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

internal class AuthorizationEndpointClient(
    private val credentialIssuerId: CredentialIssuerId,
    private val authorizationIssuer: String,
    private val authorizationEndpoint: URL,
    private val pushedAuthorizationRequestEndpoint: URL?,
    private val config: OpenId4VCIConfig,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    constructor(
        credentialIssuerId: CredentialIssuerId,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        config: OpenId4VCIConfig,
        ktorHttpClientFactory: KtorHttpClientFactory,
    ) : this(
        credentialIssuerId,
        authorizationServerMetadata.issuer.value,
        authorizationServerMetadata.authorizationEndpointURI.toURL(),
        authorizationServerMetadata.pushedAuthorizationRequestEndpointURI?.toURL(),
        config,
        ktorHttpClientFactory,
    )

    private val isCredentialIssuerAuthorizationServer: Boolean
        get() = credentialIssuerId.toString() == authorizationIssuer

    private val supportsPar: Boolean
        get() = pushedAuthorizationRequestEndpoint != null

    suspend fun submitParOrCreateAuthorizationRequestUrl(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> {
        val usePar = when (config.parUsage) {
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
    private suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> = runCatching {
        require(scopes.isNotEmpty() || credentialsConfigurationIds.isNotEmpty()) {
            "No scopes or authorization details provided. Cannot submit par."
        }

        val parEndpoint = pushedAuthorizationRequestEndpoint?.toURI()
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
                    if (!isCredentialIssuerAuthorizationServer) {
                        resource(credentialIssuerId.value.value.toURI())
                    }
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

    private fun authorizationRequestUrl(
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
            endpointURI(authorizationEndpoint.toURI())
            redirectionURI(config.authFlowRedirectionURI)
            codeChallenge(codeVerifier, CodeChallengeMethod.S256)
            state(State(state))
            issuerState?.let { customParameter("issuer_state", issuerState) }
            if (credentialsScopes.isNotEmpty()) {
                scope(NimbusScope(*credentialsScopes.map { it.value }.toTypedArray()))
                if (!isCredentialIssuerAuthorizationServer) {
                    resource(credentialIssuerId.value.value.toURI())
                }
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
                val httpsUrl = URLBuilder(Url(authorizationEndpoint.toURI())).apply {
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
            if (!isCredentialIssuerAuthorizationServer) {
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
