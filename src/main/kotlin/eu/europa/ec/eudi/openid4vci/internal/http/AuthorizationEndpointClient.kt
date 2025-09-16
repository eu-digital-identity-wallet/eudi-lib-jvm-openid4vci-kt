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
import com.nimbusds.openid.connect.sdk.Prompt
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.AccessTokenRequestFailed
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.PushedAuthorizationRequestFailed
import eu.europa.ec.eudi.openid4vci.internal.clientAttestationHeaders
import eu.europa.ec.eudi.openid4vci.internal.generateClientAttestationIfNeeded
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import com.nimbusds.oauth2.sdk.Scope as NimbusScope

/**
 * Sealed hierarchy of possible responses to a Pushed Authorization Request.
 */
internal sealed interface PushedAuthorizationRequestResponseTO : java.io.Serializable {

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
 * The context of an Authorization Request.
 */
internal data class AuthorizationRequestContext(
    val authorizationUrl: HttpsUrl,
    val pkceVerifier: PKCEVerifier,
    val abcaChallenge: Nonce?,
    val dpopNonce: Nonce?,
) : java.io.Serializable

internal class AuthorizationEndpointClient(
    private val credentialIssuerId: CredentialIssuerId,
    private val authorizationIssuer: String,
    private val authorizationEndpoint: URL,
    private val pushedAuthorizationRequestEndpoint: URL?,
    private val challengeEndpoint: URL?,
    private val config: OpenId4VCIConfig,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val httpClient: HttpClient,
) {

    constructor(
        credentialIssuerId: CredentialIssuerId,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        config: OpenId4VCIConfig,
        dPoPJwtFactory: DPoPJwtFactory?,
        httpClient: HttpClient,
    ) : this(
        credentialIssuerId,
        authorizationServerMetadata.issuer.value,
        authorizationEndpoint = authorizationServerMetadata.authorizationEndpointURI.toURL(),
        pushedAuthorizationRequestEndpoint = authorizationServerMetadata.pushedAuthorizationRequestEndpointURI?.toURL(),
        challengeEndpoint = authorizationServerMetadata.challengeEndpointURI?.toURL(),
        config,
        dPoPJwtFactory,
        httpClient,
    )

    private val isCredentialIssuerAuthorizationServer: Boolean
        get() = credentialIssuerId.toString() == authorizationIssuer

    private val supportsPar: Boolean
        get() = pushedAuthorizationRequestEndpoint != null

    private val challengeEndpointClient: ChallengeEndpointClient? by lazy {
        challengeEndpoint?.let { ChallengeEndpointClient(it, httpClient) }
    }

    suspend fun submitParOrCreateAuthorizationRequestUrl(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
    ): Result<AuthorizationRequestContext> {
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
                .map { (pkceVerifier, authorizationUrl) ->
                    AuthorizationRequestContext(
                        authorizationUrl = authorizationUrl,
                        pkceVerifier = pkceVerifier,
                        abcaChallenge = null,
                        dpopNonce = null,
                    )
                }
        }
    }

    /**
     * Submit Pushed Authorization Request for authorizing an issuance request.
     *
     * @param scopes    The scopes of the authorization request.
     * @param state     The oauth2 specific 'state' request parameter.
     * @param issuerState   The state passed from credential issuer during the negotiation phase of the issuance.
     * @return The result of the request as a pair of the PKCE verifier used during the request and the authorization code
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
    ): Result<AuthorizationRequestContext> = runCatching {
        require(scopes.isNotEmpty() || credentialsConfigurationIds.isNotEmpty()) {
            "No scopes or authorization details provided. Cannot submit par."
        }

        val parEndpoint = pushedAuthorizationRequestEndpoint?.toURI()
        checkNotNull(parEndpoint) { "PAR endpoint not advertised" }
        val clientID = ClientID(config.client.id)
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
                    authorizationDetails(
                        credentialsConfigurationIds.map {
                            it.toNimbusAuthDetail(
                                includeLocations = !isCredentialIssuerAuthorizationServer,
                                credentialIssuerId = credentialIssuerId,
                            )
                        },
                    )
                }
            }.build()
            PushedAuthorizationRequest(parEndpoint, request)
        }
        val parResponse = pushAuthorizationRequest(parEndpoint, pushedAuthorizationRequest)
        val (pkceVerifier, url) = parResponse.response.authorizationCodeUrlOrFail(clientID, codeVerifier, state)
        AuthorizationRequestContext(
            authorizationUrl = url,
            pkceVerifier = pkceVerifier,
            abcaChallenge = parResponse.abcaChallenge,
            dpopNonce = parResponse.dpopNonce,
        )
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

        val clientID = ClientID(config.client.id)
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
                authorizationDetails(
                    credentialsAuthorizationDetails.map {
                        it.toNimbusAuthDetail(
                            includeLocations = !isCredentialIssuerAuthorizationServer,
                            credentialIssuerId = credentialIssuerId,
                        )
                    },
                )
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

        is PushedAuthorizationRequestResponseTO.Failure ->
            throw PushedAuthorizationRequestFailed(error, errorDescription)
    }

    private suspend fun pushAuthorizationRequest(
        parEndpoint: URI,
        pushedAuthorizationRequest: PushedAuthorizationRequest,
    ): PushedAuthorizationRequestResponse {
        val url = parEndpoint.toURL()
        val formParameters = run {
            val fps = pushedAuthorizationRequest.asFormPostParams()
            Parameters.build {
                fps.entries.forEach { (k, v) -> append(k, v) }
            }
        }

        tailrec suspend fun requestInternal(
            existingAbcaChallenge: Nonce?,
            existingDpopNonce: Nonce?,
            abcaChallengeRetried: Boolean,
            dpopNonceRetried: Boolean,
        ): PushedAuthorizationRequestResponse {
            val dpopProof =
                dPoPJwtFactory?.createDPoPJwt(Htm.POST, url, null, existingDpopNonce)
                    ?.getOrThrow()?.serialize()

            val abcaChallenge = when (config.client) {
                is Client.Attested -> existingAbcaChallenge ?: challengeEndpointClient?.getChallenge()?.getOrThrow()
                else -> null
            }

            val response = httpClient.submitForm(url.toString(), formParameters) {
                config.generateClientAttestationIfNeeded(URI(authorizationIssuer).toURL(), abcaChallenge)?.let {
                    clientAttestationHeaders(it)
                }
                dpopProof?.let { header(DPoP, dpopProof) }
            }

            return when {
                response.status.isSuccess() -> {
                    val responseTO = response.body<PushedAuthorizationRequestResponseTO.Success>()
                    val newAbcaChallenge = response.abcaChallege()
                    val newDopNonce = response.dpopNonce()
                    PushedAuthorizationRequestResponse(
                        responseTO,
                        abcaChallenge = newAbcaChallenge ?: abcaChallenge,
                        dpopNonce = newDopNonce ?: existingDpopNonce,
                    )
                }

                response.status == HttpStatusCode.BadRequest -> {
                    val errorTO = response.body<PushedAuthorizationRequestResponseTO.Failure>()
                    val newAbcaChallenge = response.abcaChallege()
                    val newDopNonce = response.dpopNonce()

                    when {
                        errorTO.error == "use_dpop_nonce" && newDopNonce != null && !dpopNonceRetried -> {
                            requestInternal(
                                existingAbcaChallenge = newAbcaChallenge ?: abcaChallenge,
                                existingDpopNonce = newDopNonce,
                                abcaChallengeRetried = abcaChallengeRetried,
                                dpopNonceRetried = true,
                            )
                        }

                        errorTO.error == AttestationBasedClientAuthenticationSpec.USE_ATTESTATION_CHALLENGE_ERROR &&
                            !abcaChallengeRetried -> {
                            check(null != newAbcaChallenge) {
                                "Authorization Server replied with " +
                                    "'${AttestationBasedClientAuthenticationSpec.USE_ATTESTATION_CHALLENGE_ERROR}' " +
                                    "error code, but hasn't provided a challenge using the " +
                                    "'${AttestationBasedClientAuthenticationSpec.CHALLENGE_HEADER}' header"
                            }

                            requestInternal(
                                existingAbcaChallenge = newAbcaChallenge,
                                existingDpopNonce = newDopNonce ?: existingDpopNonce,
                                abcaChallengeRetried = true,
                                dpopNonceRetried = dpopNonceRetried,
                            )
                        }

                        else -> PushedAuthorizationRequestResponse(
                            errorTO,
                            abcaChallenge = newAbcaChallenge ?: existingAbcaChallenge,
                            dpopNonce = newDopNonce ?: existingDpopNonce,
                        )
                    }
                }

                else -> throw AccessTokenRequestFailed("Token request failed with ${response.status}", "N/A")
            }
        }

        return requestInternal(
            existingAbcaChallenge = null,
            existingDpopNonce = null,
            abcaChallengeRetried = false,
            dpopNonceRetried = false,
        )
    }

    private fun PushedAuthorizationRequest.asFormPostParams(): Map<String, String> =
        authorizationRequest.toParameters().mapValues { (_, value) -> value[0] }.toMap()
}

private object AuthorizationEndpointParams {
    const val PARAM_CLIENT_ID = "client_id"
    const val PARAM_REQUEST_URI = "request_uri"
    const val PARAM_STATE = "state"
}

private data class PushedAuthorizationRequestResponse(
    val response: PushedAuthorizationRequestResponseTO,
    val abcaChallenge: Nonce?,
    val dpopNonce: Nonce?,
) : java.io.Serializable
