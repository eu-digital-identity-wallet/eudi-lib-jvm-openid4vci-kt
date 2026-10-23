/*
 * Copyright (c) 2023-2026 European Commission
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
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.AccessTokenRequestFailed
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.PushedAuthorizationRequestFailed
import eu.europa.ec.eudi.openid4vci.internal.clientAttestationHeaders
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
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

internal class AuthorizationEndpointClient(
    private val credentialIssuerId: CredentialIssuerId,
    private val authorizationIssuer: String,
    private val authorizationEndpoint: HttpsUrl,
    private val pushedAuthorizationRequestEndpoint: HttpsUrl?,
    private val challengeEndpoint: HttpsUrl?,
    private val config: OpenId4VCIConfig,
    private val dPoPJwtFactory: suspend () -> DPoPJwtFactory?,
    private val provisionedClientAttestation: suspend () -> ProvisionClientAttestation.Provisioned?,
    private val httpClient: HttpClient,
) {
    constructor(
        credentialIssuerId: CredentialIssuerId,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        config: OpenId4VCIConfig,
        dPoPJwtFactory: suspend () -> DPoPJwtFactory?,
        provisionedClientAttestation: suspend () -> ProvisionClientAttestation.Provisioned?,
        httpClient: HttpClient,
    ) : this(
        credentialIssuerId,
        authorizationServerMetadata.issuer.value,
        authorizationEndpoint =
            HttpsUrl(
                requireNotNull(authorizationServerMetadata.authorizationEndpointURI) {
                    "missing authorization_endpoint"
                }.toString(),
            ).getOrThrow(),
        pushedAuthorizationRequestEndpoint =
            authorizationServerMetadata.pushedAuthorizationRequestEndpointURI
                ?.let { HttpsUrl(it.toString()).getOrThrow() },
        challengeEndpoint =
            authorizationServerMetadata.challengeEndpointURI
                ?.let { HttpsUrl(it.toString()).getOrThrow() },
        config,
        dPoPJwtFactory,
        provisionedClientAttestation,
        httpClient,
    )

    private val isCredentialIssuerAuthorizationServer: Boolean
        get() = credentialIssuerId.toString() == authorizationIssuer

    private val authorizationCodeGrant: SupportedGrants.AuthorizationCode?
        get() = config.authorizationCodeGrant

    private val supportsPar: Boolean
        get() = pushedAuthorizationRequestEndpoint != null

    private suspend fun resolveDpopJktOrThrow(): String? {
        val factory =
            dPoPJwtFactory()
                ?: throw IllegalStateException(
                    "Authorization Code DPoP binding via 'dpop_jkt' requires DPoP to be configured (dPoPUsage).",
                )
        return factory.dPoPJkt
            ?: throw IllegalStateException(
                "Authorization Code DPoP binding via 'dpop_jkt' requires a ProvisionDPoPSigner that " +
                    "exposes the DPoP public key thumbprint.",
            )
    }

    private val challengeEndpointClient: ChallengeEndpointClient? by lazy {
        challengeEndpoint?.let { ChallengeEndpointClient(it, httpClient) }
    }

    private val getAbcaChallengeAndDPoPNonce by lazy {
        GetAbcaChallengeAndDPoPNonce(provisionedClientAttestation, challengeEndpointClient)
    }

    /**
     * Submits a Pushed Authorization Request to the PAR endpoint, or, when PAR is not used, creates the URL of the
     * authorization request to the authorization endpoint.
     *
     * In the non-PAR case, code DPoP binding (when enabled) is performed by including the `dpop_jkt` parameter in
     * the authorization request, per RFC 9449 §10.1; the DPoP header cannot be used.
     */
    suspend fun submitParOrCreateAuthorizationRequestUrl(
        scopes: List<Scope>,
        credentialsConfigurationIds: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
        additionalParameters: AdditionalParameters?,
    ): Result<Triple<PKCEVerifier, HttpsUrl, Nonce?>> {
        val usePar =
            when (authorizationCodeGrant?.parUsage ?: ParUsage.Never) {
                ParUsage.Never -> {
                    false
                }

                ParUsage.IfSupported -> {
                    supportsPar
                }

                ParUsage.Required -> {
                    require(supportsPar) {
                        "PAR uses is required, yet authorization server doesn't advertise PAR endpoint"
                    }
                    true
                }
            }
        return if (usePar) {
            val authorizationCodeDPoPBindingMethod =
                authorizationCodeGrant?.authorizationCodeDPoPBindingMethod ?: AuthorizationCodeDPoPBindingMethod.None
            submitPushedAuthorizationRequest(
                scopes,
                credentialsConfigurationIds,
                state,
                issuerState,
                authorizationCodeDPoPBindingMethod,
                additionalParameters,
            )
        } else {
            val authorizationCodeDPoPBindingMethod =
                authorizationCodeGrant?.authorizationCodeDPoPBindingMethod ?: AuthorizationCodeDPoPBindingMethod.None
            authorizationRequestUrl(
                scopes,
                credentialsConfigurationIds,
                state,
                issuerState,
                authorizationCodeDPoPBindingMethod,
                additionalParameters,
            ).map { (a, b) ->
                Triple(a, b, null)
            }
        }
    }

    /**
     * Submit Pushed Authorization Request for authorizing an issuance request.
     *
     * @param scopes    The scopes of the authorization request.
     * @param state     The oauth2 specific 'state' request parameter.
     * @param issuerState   The state passed from credential issuer during the negotiation phase of the issuance.
     * @param authorizationCodeDPoPBindingMethod How the Authorization Code is bound to the DPoP key, per RFC 9449 §10.1.
     * @param additionalParameters optional parameters appended to the authorization request
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
        authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod,
        additionalParameters: AdditionalParameters?,
    ): Result<Triple<PKCEVerifier, HttpsUrl, Nonce?>> =
        runCatchingCancellable {
            require(scopes.isNotEmpty() || credentialsConfigurationIds.isNotEmpty()) {
                "No scopes or authorization details provided. Cannot submit par."
            }

            val parEndpoint = pushedAuthorizationRequestEndpoint?.value?.toURI()
            checkNotNull(parEndpoint) { "PAR endpoint not advertised" }
            val clientID = ClientID(config.clientAuthentication.id)
            val codeVerifier = CodeVerifier()
            val redirectionURI =
                checkNotNull(authorizationCodeGrant) {
                    "Authorization Code grant is not configured"
                }.authFlowRedirectionURI
            val pushedAuthorizationRequest =
                run {
                    val request =
                        AuthorizationRequest
                            .Builder(ResponseType.CODE, clientID)
                            .apply {
                                redirectionURI(redirectionURI)
                                codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                                state(State(state))
                                issuerState?.let { customParameter("issuer_state", issuerState) }
                                additionalParameters?.params?.forEach { (key, value) ->
                                    customParameter(key, value)
                                }
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
            val (response, dpopNonce) =
                pushAuthorizationRequest(
                    parEndpoint,
                    pushedAuthorizationRequest,
                    authorizationCodeDPoPBindingMethod,
                )
            val (pkceVerifier, url) = response.authorizationCodeUrlOrFail(clientID, codeVerifier)
            Triple(pkceVerifier, url, dpopNonce)
        }

    /**
     * Creates the URL of the authorization request to the authorization endpoint, i.e. the non-PAR case.
     *
     * When code DPoP binding is enabled ([AuthorizationCodeDPoPBindingMethod.DPoPJkt] or
     * [AuthorizationCodeDPoPBindingMethod.DPoPHeader]), the `dpop_jkt` parameter is included in the authorization
     * request to bind the Authorization Code to the DPoP key, per RFC 9449 §10.1. The DPoP header cannot be used
     * here, so [AuthorizationCodeDPoPBindingMethod.DPoPHeader] falls back to `dpop_jkt`.
     */
    private suspend fun authorizationRequestUrl(
        credentialsScopes: List<Scope>,
        credentialsAuthorizationDetails: List<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: String?,
        authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod,
        additionalParameters: AdditionalParameters?,
    ): Result<Pair<PKCEVerifier, HttpsUrl>> =
        runCatchingCancellable {
            require(credentialsScopes.isNotEmpty() || credentialsAuthorizationDetails.isNotEmpty()) {
                "No scopes or authorization details provided. Cannot prepare authorization request."
            }
            val dpopJkt =
                if (authorizationCodeDPoPBindingMethod != AuthorizationCodeDPoPBindingMethod.None) {
                    resolveDpopJktOrThrow()
                } else {
                    null
                }

            val clientID = ClientID(config.clientAuthentication.id)
            val codeVerifier = CodeVerifier()
            val redirectionURI =
                checkNotNull(authorizationCodeGrant) {
                    "Authorization Code grant is not configured"
                }.authFlowRedirectionURI
            val authorizationRequest =
                AuthorizationRequest
                    .Builder(ResponseType.CODE, clientID)
                    .apply {
                        endpointURI(authorizationEndpoint.value.toURI())
                        redirectionURI(redirectionURI)
                        codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                        state(State(state))
                        issuerState?.let { customParameter("issuer_state", issuerState) }
                        additionalParameters?.params?.forEach { (key, value) ->
                            customParameter(key, value)
                        }
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
                        dpopJkt?.let { customParameter(AuthorizationEndpointParams.PARAM_DPOP_JKT, it) }
                    }.build()

            val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
            val url = HttpsUrl(authorizationRequest.toURI().toString()).getOrThrow()
            pkceVerifier to url
        }

    private fun PushedAuthorizationRequestResponseTO.authorizationCodeUrlOrFail(
        clientID: ClientID,
        codeVerifier: CodeVerifier,
    ): Pair<PKCEVerifier, HttpsUrl> =
        when (this) {
            is PushedAuthorizationRequestResponseTO.Success -> {
                val authorizationCodeUrl =
                    run {
                        val httpsUrl =
                            URLBuilder(Url(authorizationEndpoint.value.toURI()))
                                .apply {
                                    parameters.append(AuthorizationEndpointParams.PARAM_CLIENT_ID, clientID.value)
                                    parameters.append(AuthorizationEndpointParams.PARAM_REQUEST_URI, requestURI)
                                }.build()
                        HttpsUrl(httpsUrl.toString()).getOrThrow()
                    }
                val pkceVerifier = PKCEVerifier(codeVerifier.value, CodeChallengeMethod.S256.toString())
                pkceVerifier to authorizationCodeUrl
            }

            is PushedAuthorizationRequestResponseTO.Failure -> {
                throw PushedAuthorizationRequestFailed(error, errorDescription)
            }
        }

    private suspend fun pushAuthorizationRequest(
        parEndpoint: URI,
        pushedAuthorizationRequest: PushedAuthorizationRequest,
        authorizationCodeDPoPBindingMethod: AuthorizationCodeDPoPBindingMethod,
    ): Pair<PushedAuthorizationRequestResponseTO, Nonce?> {
        val url = parEndpoint.toURL()
        val dpopJkt =
            if (authorizationCodeDPoPBindingMethod == AuthorizationCodeDPoPBindingMethod.DPoPJkt) {
                resolveDpopJktOrThrow()
            } else {
                null
            }
        val formParameters =
            run {
                val fps = pushedAuthorizationRequest.asFormPostParams()
                Parameters.build {
                    fps.entries.forEach { (k, v) -> append(k, v) }
                    dpopJkt?.let { append(AuthorizationEndpointParams.PARAM_DPOP_JKT, it) }
                }
            }

        tailrec suspend fun requestInternal(
            existingAbcaChallenge: Nonce?,
            existingDpopNonce: Nonce?,
            abcaChallengeRetried: Boolean,
            dpopNonceRetried: Boolean,
        ): Pair<PushedAuthorizationRequestResponseTO, Nonce?> {
            val (abcaChallenge, dpopNonce) =
                getAbcaChallengeAndDPoPNonce(
                    existingAbcaChallenge = existingAbcaChallenge,
                    existingDpopNonce = existingDpopNonce,
                )
            val dpopProof =
                if (authorizationCodeDPoPBindingMethod == AuthorizationCodeDPoPBindingMethod.DPoPHeader)
                    dPoPJwtFactory()
                        ?.createDPoPJwt(Htm.POST, url, null, dpopNonce)
                        ?.getOrThrow()
                        ?.serialize()
                else
                    null
            val clientAttestation =
                provisionedClientAttestation()?.generateClientAttestation(
                    config.clock,
                    config.clientAuthentication.id,
                    URI(authorizationIssuer).toURL(),
                    abcaChallenge,
                )

            val response =
                httpClient.submitForm(url.toString(), formParameters) {
                    clientAttestation?.let { clientAttestationHeaders(it) }
                    dpopProof?.let { header(DPoP, dpopProof) }
                }

            return when {
                response.status.isSuccess() -> {
                    val responseTO = response.body<PushedAuthorizationRequestResponseTO.Success>()
                    val newDopNonce = response.dpopNonce()
                    responseTO to (newDopNonce ?: dpopNonce)
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
                            null != newAbcaChallenge &&
                            !abcaChallengeRetried -> {
                            requestInternal(
                                existingAbcaChallenge = newAbcaChallenge,
                                existingDpopNonce = newDopNonce ?: dpopNonce,
                                abcaChallengeRetried = true,
                                dpopNonceRetried = dpopNonceRetried,
                            )
                        }

                        else -> {
                            errorTO to (newDopNonce ?: dpopNonce)
                        }
                    }
                }

                else -> {
                    throw AccessTokenRequestFailed("Token request failed with ${response.status}", "N/A")
                }
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
    const val PARAM_DPOP_JKT = "dpop_jkt"
}
