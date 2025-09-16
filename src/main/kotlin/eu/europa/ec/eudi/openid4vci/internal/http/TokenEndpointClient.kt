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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.AccessTokenRequestFailed
import eu.europa.ec.eudi.openid4vci.Grants.PreAuthorizedCode
import eu.europa.ec.eudi.openid4vci.internal.GrantedAuthorizationDetailsSerializer
import eu.europa.ec.eudi.openid4vci.internal.Tokens
import eu.europa.ec.eudi.openid4vci.internal.clientAttestationHeaders
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.time.Clock

/**
 * Sealed hierarchy of possible responses to an Access Token request.
 */
internal sealed interface TokenResponseTO {

    /**
     * Successful request submission.
     *
     * @param accessToken The access token.
     * @param expiresIn Token time to live.
     */
    @Serializable
    data class Success(
        @SerialName("token_type") val tokenType: String? = null,
        @SerialName("access_token") val accessToken: String,
        @SerialName("refresh_token") val refreshToken: String? = null,
        @SerialName("expires_in") val expiresIn: Long? = null,
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

    fun tokensOrFail(clock: Clock): Tokens =
        when (this) {
            is Success -> {
                Tokens(
                    accessToken = AccessToken(
                        accessToken = accessToken,
                        expiresInSec = expiresIn,
                        useDPoP = DPoP.equals(other = tokenType, ignoreCase = true),
                    ),
                    refreshToken = refreshToken?.let { RefreshToken(it) },
                    authorizationDetails = authorizationDetails ?: emptyMap(),
                    timestamp = clock.instant(),
                )
            }

            is Failure -> throw AccessTokenRequestFailed(error, errorDescription)
        }
}

internal class TokensResponse(
    val tokens: Tokens,
    val abcaChallenge: Nonce?,
    val dpopNonce: Nonce?,
)

internal class TokenEndpointClient(
    private val credentialIssuerId: CredentialIssuerId,
    private val clock: Clock,
    private val client: Client,
    private val authFlowRedirectionURI: URI,
    private val authServerId: URL,
    private val challengeEndpoint: URL?,
    private val tokenEndpoint: URL,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val clientAttestationPoPBuilder: ClientAttestationPoPBuilder,
    private val httpClient: HttpClient,
) {

    private val isCredentialIssuerAuthorizationServer: Boolean
        get() = credentialIssuerId.toString() == authServerId.toString()

    private val challengeEndpointClient: ChallengeEndpointClient? by lazy {
        challengeEndpoint?.let { ChallengeEndpointClient(it, httpClient) }
    }

    constructor(
        credentialIssuerId: CredentialIssuerId,
        authorizationServerMetadata: CIAuthorizationServerMetadata,
        config: OpenId4VCIConfig,
        dPoPJwtFactory: DPoPJwtFactory?,
        httpClient: HttpClient,
    ) : this(
        credentialIssuerId,
        config.clock,
        config.client,
        authFlowRedirectionURI = config.authFlowRedirectionURI,
        authServerId = URI(authorizationServerMetadata.issuer.value).toURL(),
        challengeEndpoint = authorizationServerMetadata.challengeEndpointURI?.toURL(),
        tokenEndpoint = authorizationServerMetadata.tokenEndpointURI.toURL(),
        dPoPJwtFactory,
        config.clientAttestationPoPBuilder,
        httpClient,
    )

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * authorization code flow
     *
     * @param authorizationCode The authorization code generated from authorization server.
     * @param pkceVerifier  The code verifier that was used when submitting the Pushed Authorization Request.
     * @param credConfigIdsAsAuthDetails The list of [CredentialConfigurationIdentifier]s that have been passed to authorization server
     * as authorization details, part of a Rich Authorization Request.
     * @return The result of the request as a pair of the access token and the optional DPoP nonce returned by the endpoint.
     */
    suspend fun requestAccessTokenAuthFlow(
        authorizationCode: AuthorizationCode,
        pkceVerifier: PKCEVerifier,
        credConfigIdsAsAuthDetails: List<CredentialConfigurationIdentifier> = emptyList(),
        abcaChallenge: Nonce?,
        dpopNonce: Nonce?,
    ): Result<TokensResponse> = runCatching {
        // Append authorization_details form param if needed
        val authDetails = credConfigIdsAsAuthDetails.takeIf { it.isNotEmpty() }?.let {
            authorizationDetailsFormParam(credConfigIdsAsAuthDetails)
        }
        val params =
            TokenEndpointForm.authCodeFlow(
                clientId = client.id,
                authorizationCode = authorizationCode,
                redirectionURI = authFlowRedirectionURI,
                pkceVerifier = pkceVerifier,
                authorizationDetails = authDetails,
            )
        placeTokenRequest(params, abcaChallenge = abcaChallenge, dpopNonce = dpopNonce)
    }

    /**
     * Submits a request for access token in authorization server's token endpoint passing parameters specific to the
     * pre-authorization code flow
     *
     * @param preAuthorizedCode The pre-authorization code.
     * @param txCode  Extra transaction code to be passed if specified as required in the credential offer.
     * @param credConfigIdsAsAuthDetails  A list of credential configuration ids to be sent as 'authorization_details'.
     * @param dpopNonce  A DPoP nonce.
     * @return The result of the request as a pair of the access token and the optional DPoP nonce returned by the endpoint.
     */
    suspend fun requestAccessTokenPreAuthFlow(
        preAuthorizedCode: PreAuthorizedCode,
        txCode: String?,
        credConfigIdsAsAuthDetails: List<CredentialConfigurationIdentifier> = emptyList(),
        abcaChallenge: Nonce?,
        dpopNonce: Nonce?,
    ): Result<TokensResponse> = runCatching {
        // Append authorization_details form param if needed
        val authDetails = credConfigIdsAsAuthDetails.takeIf { it.isNotEmpty() }?.let {
            authorizationDetailsFormParam(credConfigIdsAsAuthDetails)
        }
        val params =
            TokenEndpointForm.preAuthCodeFlow(
                clientId = client.id,
                preAuthorizedCode = preAuthorizedCode,
                txCode = txCode,
                authorizationDetails = authDetails,
            )
        placeTokenRequest(params, abcaChallenge = abcaChallenge, dpopNonce = dpopNonce)
    }

    /**
     * Submits a request for refreshing an access token in authorization server's token endpoint passing
     * the refresh token
     * @param refreshToken the token to be used for refreshing the access token
     *
     * @return the token end point response, which will include a new [Tokens.accessToken] and possibly
     * a new [Tokens.refreshToken]
     */
    suspend fun refreshAccessToken(
        refreshToken: RefreshToken,
        abcaChallenge: Nonce?,
        dpopNonce: Nonce?,
    ): Result<TokensResponse> = runCatching {
        val params = TokenEndpointForm.refreshAccessToken(client.id, refreshToken)
        placeTokenRequest(params, abcaChallenge = abcaChallenge, dpopNonce = dpopNonce)
    }

    private suspend fun placeTokenRequest(
        params: Map<String, String>,
        abcaChallenge: Nonce?,
        dpopNonce: Nonce?,
    ): TokensResponse {
        tailrec suspend fun requestInternal(
            existingAbcaChallenge: Nonce?,
            existingDpopNonce: Nonce?,
            retriedAbcaChallenge: Boolean,
            retriedDPoPNonce: Boolean,
        ): TokensResponse {
            val response = run {
                val formParameters = Parameters.build {
                    params.entries.forEach { (k, v) -> append(k, v) }
                }
                val jwt =
                    dPoPJwtFactory?.createDPoPJwt(Htm.POST, tokenEndpoint, null, existingDpopNonce)
                        ?.getOrThrow()?.serialize()

                val abcaChallenge = when (client) {
                    is Client.Attested -> existingAbcaChallenge ?: challengeEndpointClient?.getChallenge()?.getOrThrow()
                    else -> null
                }

                httpClient.submitForm(tokenEndpoint.toString(), formParameters) {
                    jwt?.let { header(DPoP, jwt) }
                    generateClientAttestationIfNeeded(abcaChallenge)?.let(::clientAttestationHeaders)
                }
            }

            return when {
                response.status.isSuccess() -> {
                    val responseTO = response.body<TokenResponseTO.Success>()
                    val newAbcaChallenge = response.abcaChallege()
                    val newDopNonce = response.dpopNonce()
                    TokensResponse(
                        responseTO.tokensOrFail(clock),
                        abcaChallenge = newAbcaChallenge ?: abcaChallenge,
                        dpopNonce = newDopNonce ?: existingDpopNonce,
                    )
                }

                response.status == HttpStatusCode.BadRequest -> {
                    val errorTO = response.body<TokenResponseTO.Failure>()
                    val newAbcaChallenge = response.abcaChallege()
                    val newDopNonce = response.dpopNonce()
                    when {
                        errorTO.error == "use_dpop_nonce" && newDopNonce != null && !retriedDPoPNonce -> {
                            requestInternal(
                                existingAbcaChallenge = newAbcaChallenge ?: abcaChallenge,
                                existingDpopNonce = newDopNonce,
                                retriedAbcaChallenge = retriedAbcaChallenge,
                                retriedDPoPNonce = true,
                            )
                        }

                        errorTO.error == AttestationBasedClientAuthenticationSpec.USE_ATTESTATION_CHALLENGE_ERROR &&
                            !retriedAbcaChallenge -> {
                            check(null != newAbcaChallenge) {
                                "Authorization Server replied with " +
                                    "'${AttestationBasedClientAuthenticationSpec.USE_ATTESTATION_CHALLENGE_ERROR}' " +
                                    "error code, but hasn't provided a challenge using the " +
                                    "'${AttestationBasedClientAuthenticationSpec.CHALLENGE_HEADER}' header"
                            }

                            requestInternal(
                                existingAbcaChallenge = newAbcaChallenge,
                                existingDpopNonce = newDopNonce ?: existingDpopNonce,
                                retriedAbcaChallenge = true,
                                retriedDPoPNonce = retriedDPoPNonce,
                            )
                        }

                        else -> throw AccessTokenRequestFailed(errorTO.error, errorTO.errorDescription)
                    }
                }

                else -> throw AccessTokenRequestFailed("Token request failed with ${response.status}", "N/A")
            }
        }

        return requestInternal(
            existingAbcaChallenge = abcaChallenge,
            existingDpopNonce = dpopNonce,
            retriedAbcaChallenge = false,
            retriedDPoPNonce = false,
        )
    }

    private fun authorizationDetailsFormParam(
        credentialConfigurationIds: List<CredentialConfigurationIdentifier>,
    ): String {
        require(credentialConfigurationIds.isNotEmpty())
        return credentialConfigurationIds.map {
            it.toNimbusAuthDetail(
                includeLocations = isCredentialIssuerAuthorizationServer,
                credentialIssuerId = credentialIssuerId,
            )
        }
            .toFormParamString()
    }

    private fun generateClientAttestationIfNeeded(challenge: Nonce?): ClientAttestation? =
        when (client) {
            is Client.Attested ->
                with(clientAttestationPoPBuilder) {
                    val popJWT = client.attestationPoPJWT(clock, authServerId, challenge)
                    client.attestationJWT to popJWT
                }

            else -> null
        }
}

internal object TokenEndpointForm {
    const val AUTHORIZATION_CODE_GRANT = "authorization_code"
    const val PRE_AUTHORIZED_CODE_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    const val REFRESH_TOKEN = "refresh_token"
    const val REDIRECT_URI_PARAM = "redirect_uri"
    const val CODE_VERIFIER_PARAM = "code_verifier"
    const val AUTHORIZATION_CODE_PARAM = "code"
    const val CLIENT_ID_PARAM = "client_id"
    const val GRANT_TYPE_PARAM = "grant_type"
    const val TX_CODE_PARAM = "tx_code"
    const val PRE_AUTHORIZED_CODE_PARAM = "pre-authorized_code"
    const val REFRESH_TOKEN_PARAM = "refresh_token"
    const val AUTHORIZATION_DETAILS = "authorization_details"

    fun authCodeFlow(
        clientId: ClientId,
        authorizationCode: AuthorizationCode,
        redirectionURI: URI,
        pkceVerifier: PKCEVerifier,
        authorizationDetails: String?,
    ): Map<String, String> =
        buildMap {
            put(CLIENT_ID_PARAM, clientId)
            put(GRANT_TYPE_PARAM, AUTHORIZATION_CODE_GRANT)
            put(AUTHORIZATION_CODE_PARAM, authorizationCode.code)
            put(REDIRECT_URI_PARAM, redirectionURI.toString())
            put(CODE_VERIFIER_PARAM, pkceVerifier.codeVerifier)
            authorizationDetails?.let { put(AUTHORIZATION_DETAILS, it) }
        }.toMap()

    fun preAuthCodeFlow(
        clientId: ClientId,
        preAuthorizedCode: PreAuthorizedCode,
        txCode: String?,
        authorizationDetails: String?,
    ): Map<String, String> =
        buildMap {
            put(CLIENT_ID_PARAM, clientId)
            put(GRANT_TYPE_PARAM, PRE_AUTHORIZED_CODE_GRANT)
            put(PRE_AUTHORIZED_CODE_PARAM, preAuthorizedCode.preAuthorizedCode)
            txCode?.let { put(TX_CODE_PARAM, it) }
            authorizationDetails?.let { put(AUTHORIZATION_DETAILS, it) }
        }.toMap()

    fun refreshAccessToken(
        clientId: String,
        refreshToken: RefreshToken,
    ): Map<String, String> =
        buildMap {
            put(CLIENT_ID_PARAM, clientId)
            put(GRANT_TYPE_PARAM, REFRESH_TOKEN)
            put(REFRESH_TOKEN_PARAM, refreshToken.refreshToken)
        }
}
