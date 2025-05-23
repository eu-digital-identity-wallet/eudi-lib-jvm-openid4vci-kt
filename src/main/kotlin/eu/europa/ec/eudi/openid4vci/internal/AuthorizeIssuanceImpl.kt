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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.AccessTokenOption.AsRequested
import eu.europa.ec.eudi.openid4vci.AccessTokenOption.Limited
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidAuthorizationState
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationEndpointClient
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointClient
import java.time.Instant
import com.nimbusds.oauth2.sdk.id.State as NimbusState

internal data class TokenResponse(
    val accessToken: AccessToken,
    val refreshToken: RefreshToken?,
    val authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>> = emptyMap(),
    val timestamp: Instant,
)

internal class AuthorizeIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    private val authorizationEndpointClient: AuthorizationEndpointClient?,
    private val tokenEndpointClient: TokenEndpointClient,
) : AuthorizeIssuance {

    override suspend fun prepareAuthorizationRequest(walletState: String?): Result<AuthorizationRequestPrepared> =
        runCatching {
            requireNotNull(authorizationEndpointClient) {
                "Authorization server does not support Authorization Code Flow"
            }
            val (scopes, configurationIds) = scopesAndCredentialConfigurationIds()
            require(scopes.isNotEmpty() || configurationIds.isNotEmpty()) {
                "Either scopes or credential configuration ids must be provided"
            }
            val state = walletState ?: NimbusState().value
            val issuerState = credentialOffer.grants?.authorizationCode()?.issuerState
            val (codeVerifier, authorizationCodeUrl, dpopNonce) =
                authorizationEndpointClient.submitParOrCreateAuthorizationRequestUrl(
                    scopes,
                    configurationIds,
                    state,
                    issuerState,
                ).getOrThrow()
            AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state, configurationIds, dpopNonce)
        }

    private fun scopesAndCredentialConfigurationIds(): Pair<List<Scope>, List<CredentialConfigurationIdentifier>> {
        val scopes = mutableListOf<Scope>()
        val configurationIdentifiers = mutableListOf<CredentialConfigurationIdentifier>()
        fun credentialConfigurationById(id: CredentialConfigurationIdentifier): CredentialConfiguration {
            val issuerMetadata = credentialOffer.credentialIssuerMetadata
            return requireNotNull(issuerMetadata.credentialConfigurationsSupported[id]) {
                "$id was not found within issuer metadata"
            }
        }
        for (id in credentialOffer.credentialConfigurationIdentifiers) {
            val credentialConfiguration = credentialConfigurationById(id)
            fun authDetailsByCfgId() = configurationIdentifiers.add(id)
            fun addScope(): Boolean = credentialConfiguration.scope?.let { scopes.add(Scope(it)) } ?: false
            when (config.authorizeIssuanceConfig) {
                AuthorizeIssuanceConfig.AUTHORIZATION_DETAILS -> authDetailsByCfgId()
                AuthorizeIssuanceConfig.FAVOR_SCOPES -> if (!addScope()) authDetailsByCfgId()
            }
        }
        return scopes to configurationIdentifiers
    }

    override suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
        authDetailsOption: AccessTokenOption,
    ): Result<AuthorizedRequest> = runCatching {
        ensure(serverState == state) { InvalidAuthorizationState() }
        val credConfigIdsAsAuthDetails = identifiersSentAsAuthDetails.filter(authDetailsOption)
        val (tokenResponse, newDpopNonce) =
            tokenEndpointClient.requestAccessTokenAuthFlow(
                authorizationCode,
                pkceVerifier,
                credConfigIdsAsAuthDetails,
                dpopNonce,
            ).getOrThrow()

        AuthorizedRequest(
            accessToken = tokenResponse.accessToken,
            refreshToken = tokenResponse.refreshToken,
            credentialIdentifiers = tokenResponse.authorizationDetails,
            timestamp = tokenResponse.timestamp,
            authorizationServerDpopNonce = newDpopNonce,
            resourceServerDpopNonce = null,
            grant = Grant.AuthorizationCode,
        )
    }

    override suspend fun authorizeWithPreAuthorizationCode(
        txCode: String?,
        authDetailsOption: AccessTokenOption,
    ): Result<AuthorizedRequest> = runCatching {
        val offeredGrants = requireNotNull(credentialOffer.grants) {
            "Grant not specified in credential offer."
        }
        val preAuthorizedCode = requireNotNull(offeredGrants.preAuthorizedCode()) {
            "Pre-authorized code grant expected"
        }
        with(preAuthorizedCode) { validate(txCode) }
        val credConfigIdsAsAuthDetails =
            credentialOffer.credentialConfigurationIdentifiers.filter(authDetailsOption)

        val (tokenResponse, newDpopNonce) =
            tokenEndpointClient.requestAccessTokenPreAuthFlow(
                preAuthorizedCode,
                txCode,
                credConfigIdsAsAuthDetails,
                dpopNonce = null,
            ).getOrThrow()

        AuthorizedRequest(
            accessToken = tokenResponse.accessToken,
            refreshToken = tokenResponse.refreshToken,
            credentialIdentifiers = tokenResponse.authorizationDetails,
            timestamp = tokenResponse.timestamp,
            authorizationServerDpopNonce = newDpopNonce,
            resourceServerDpopNonce = null,
            grant = Grant.PreAuthorizedCodeGrant,
        )
    }
}

private fun Grants.PreAuthorizedCode.validate(txCode: String?) {
    val expectedTxCodeSpec = this@validate.txCode
    if (expectedTxCodeSpec != null) {
        with(expectedTxCodeSpec) { validate(txCode) }
    }
}

private fun TxCode.validate(txCode: String?) {
    require(!txCode.isNullOrEmpty()) {
        "Issuer's grant is pre-authorization code with transaction code required but no transaction code passed"
    }
    length?.let {
        require(length == txCode.length) {
            "Expected transaction code length is $length but code of length ${txCode.length} passed"
        }
    }
    if (TxCodeInputMode.NUMERIC == inputMode) {
        requireNotNull(txCode.toIntOrNull()) {
            "Issuers expects transaction code to be numeric but is not."
        }
    }
}

private fun Iterable<CredentialConfigurationIdentifier>.filter(
    accessTokenOption: AccessTokenOption,
): List<CredentialConfigurationIdentifier> =
    when (accessTokenOption) {
        AsRequested -> emptyList()
        is Limited -> filter(accessTokenOption.filter)
    }
