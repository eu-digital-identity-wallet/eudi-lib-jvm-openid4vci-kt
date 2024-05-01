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

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.NoProofRequired
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.ProofRequired
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidAuthorizationState
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationServerClient

internal data class TokenResponse(
    val accessToken: AccessToken,
    val refreshToken: RefreshToken?,
    val cNonce: CNonce?,
    val authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>> = emptyMap(),
)

internal class AuthorizeIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
    dPoPJwtFactory: DPoPJwtFactory?,
) : AuthorizeIssuance {

    private val authServerClient: AuthorizationServerClient =
        AuthorizationServerClient(
            credentialOffer.credentialIssuerIdentifier,
            credentialOffer.authorizationServerMetadata,
            config,
            dPoPJwtFactory,
            ktorHttpClientFactory,
        )

    override suspend fun prepareAuthorizationRequest(walletState: String?): Result<AuthorizationRequestPrepared> =
        runCatching {
            val (scopes, configurationIds) = scopesAndCredentialConfigurationIds()
            prepareAuthorizationRequest(walletState, scopes, configurationIds).getOrThrow()
        }

    private fun scopesAndCredentialConfigurationIds(): Pair<List<Scope>, List<CredentialConfigurationIdentifier>> {
        val scopes = mutableListOf<Scope>()
        val configurationIdentifiers = mutableListOf<CredentialConfigurationIdentifier>()
        for (id in credentialOffer.credentialConfigurationIdentifiers) {
            val credentialConfiguration = credentialConfigurationSupportedById(id)
            fun authDetailsByCfgId() = configurationIdentifiers.add(id)
            fun addScope(): Boolean = credentialConfiguration.scope?.let { scopes.add(Scope(it)) } ?: false
            when (config.authorizeIssuanceConfig) {
                AuthorizeIssuanceConfig.AUTHORIZATION_DETAILS -> authDetailsByCfgId()
                AuthorizeIssuanceConfig.FAVOR_SCOPES -> if (!addScope()) authDetailsByCfgId()
            }
        }
        return scopes to configurationIdentifiers
    }

    private suspend fun prepareAuthorizationRequest(
        walletState: String?,
        scopes: List<Scope>,
        credentialConfigurationIds: List<CredentialConfigurationIdentifier>,
    ): Result<AuthorizationRequestPrepared> = runCatching {
        require(scopes.isNotEmpty() || credentialConfigurationIds.isNotEmpty()) {
            "Either scopes or credential configuration ids must be provided"
        }
        val state = walletState ?: State().value
        val issuerState = when (credentialOffer.grants) {
            is Grants.AuthorizationCode -> credentialOffer.grants.issuerState
            is Grants.Both -> credentialOffer.grants.authorizationCode.issuerState
            else -> null
        }

        val authorizationServerSupportsPar =
            credentialOffer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI != null
        val (codeVerifier, authorizationCodeUrl) =
            with(authServerClient) {
                if (authorizationServerSupportsPar)
                    submitPushedAuthorizationRequest(scopes, credentialConfigurationIds, state, issuerState)
                else
                    authorizationRequestUrl(scopes, credentialConfigurationIds, state, issuerState)
            }.getOrThrow()

        AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state)
    }

    private fun credentialConfigurationSupportedById(
        credentialConfigurationId: CredentialConfigurationIdentifier,
    ): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]
        return requireNotNull(credentialSupported) {
            "$credentialConfigurationId was not found within issuer metadata"
        }
    }

    override suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
    ): Result<AuthorizedRequest> =
        runCatching {
            ensure(serverState == state) { InvalidAuthorizationState }
            val offerRequiresProofs = credentialOffer.requiresProofs()
            val (accessToken, refreshToken, cNonce, authDetails) =
                authServerClient.requestAccessTokenAuthFlow(authorizationCode, pkceVerifier).getOrThrow()

            when {
                cNonce != null && offerRequiresProofs -> ProofRequired(accessToken, refreshToken, cNonce, authDetails)
                else ->
                    NoProofRequired(accessToken, refreshToken, authDetails) }
        }

    override suspend fun authorizeWithPreAuthorizationCode(txCode: String?): Result<AuthorizedRequest> = runCatching {
        val offeredGrants = credentialOffer.grants
        require(offeredGrants != null) { "Grant not specified in credential offer." }
        val preAuthorizedCode = when (offeredGrants) {
            is Grants.PreAuthorizedCode -> offeredGrants
            is Grants.Both -> offeredGrants.preAuthorizedCode
            is Grants.AuthorizationCode -> error("Pre-authorized code grant expected")
        }
        preAuthorizedCode.txCode?.let {
            require(!txCode.isNullOrEmpty()) {
                "Issuer's grant is pre-authorization code with transaction code required but no transaction code passed"
            }
            preAuthorizedCode.txCode.length?.let {
                require(preAuthorizedCode.txCode.length == txCode.length) {
                    "Expected transaction code length is ${preAuthorizedCode.txCode.length} but code of length ${txCode.length} passed"
                }
            }
            if (TxCodeInputMode.NUMERIC == preAuthorizedCode.txCode.inputMode) {
                require(txCode.toIntOrNull() != null) {
                    "Issuers expects transaction code to be numeric but is not."
                }
            }
        }
        val offerRequiresProofs = credentialOffer.requiresProofs()
        val (accessToken, refreshToken, cNonce, _) = authServerClient.requestAccessTokenPreAuthFlow(
            preAuthorizedCode,
            txCode,
        ).getOrThrow()

        when {
            cNonce != null && offerRequiresProofs -> ProofRequired(accessToken, refreshToken, cNonce, emptyMap())
            else -> NoProofRequired(accessToken, refreshToken, emptyMap())
        }
    }

    private fun CredentialOffer.requiresProofs(): Boolean =
        credentialConfigurationIdentifiers.any {
            !credentialIssuerMetadata.credentialConfigurationsSupported[it]?.proofTypesSupported.isNullOrEmpty()
        }
}
