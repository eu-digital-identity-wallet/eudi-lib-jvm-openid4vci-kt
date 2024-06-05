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
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.NoProofRequired
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.ProofRequired
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidAuthorizationState
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationServerClient
import com.nimbusds.oauth2.sdk.id.State as NimbusState

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
    parUsage: ParUsage,
) : AuthorizeIssuance {

    private val authorizationServer: AuthorizationServerClient =
        AuthorizationServerClient(
            credentialOffer.credentialIssuerIdentifier,
            credentialOffer.authorizationServerMetadata,
            config,
            dPoPJwtFactory,
            ktorHttpClientFactory,
            parUsage,
        )

    override suspend fun prepareAuthorizationRequest(walletState: String?): Result<AuthorizationRequestPrepared> =
        runCatching {
            val (scopes, configurationIds) = scopesAndCredentialConfigurationIds()
            require(scopes.isNotEmpty() || configurationIds.isNotEmpty()) {
                "Either scopes or credential configuration ids must be provided"
            }
            val state = walletState ?: NimbusState().value
            val issuerState = credentialOffer.grants?.authorizationCode()?.issuerState
            val (codeVerifier, authorizationCodeUrl) =
                authorizationServer.submitParOrCreateAuthorizationRequestUrl(
                    scopes,
                    configurationIds,
                    state,
                    issuerState,
                ).getOrThrow()
            AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state)
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
    ): Result<AuthorizedRequest> =
        runCatching {
            ensure(serverState == state) { InvalidAuthorizationState }
            val tokenResponse =
                authorizationServer.requestAccessTokenAuthFlow(authorizationCode, pkceVerifier).getOrThrow()
            authorizedRequest(credentialOffer, tokenResponse)
        }

    override suspend fun authorizeWithPreAuthorizationCode(txCode: String?): Result<AuthorizedRequest> = runCatching {
        val offeredGrants = requireNotNull(credentialOffer.grants) {
            "Grant not specified in credential offer."
        }
        val preAuthorizedCode = requireNotNull(offeredGrants.preAuthorizedCode()) {
            "Pre-authorized code grant expected"
        }
        with(preAuthorizedCode) { validate(txCode) }
        val tokenResponse =
            authorizationServer.requestAccessTokenPreAuthFlow(preAuthorizedCode, txCode).getOrThrow()
        authorizedRequest(credentialOffer, tokenResponse)
    }
}

internal fun Grants.PreAuthorizedCode.validate(txCode: String?) {
    val expectedTxCodeSpec = this@validate.txCode
    if (expectedTxCodeSpec != null) {
        with(expectedTxCodeSpec) { validate(txCode) }
    }
}

internal fun TxCode.validate(txCode: String?) {
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

internal fun authorizedRequest(offer: CredentialOffer, tokenResponse: TokenResponse): AuthorizedRequest {
    val offerRequiresProofs = offer.credentialConfigurationIdentifiers.any {
        val credentialConfiguration = offer.credentialIssuerMetadata.credentialConfigurationsSupported[it]
        credentialConfiguration != null && credentialConfiguration.proofTypesSupported.values.isNotEmpty()
    }
    val (accessToken, refreshToken, cNonce, authorizationDetails) = tokenResponse
    return when {
        cNonce != null && offerRequiresProofs -> ProofRequired(accessToken, refreshToken, cNonce, authorizationDetails)
        else -> NoProofRequired(accessToken, refreshToken, authorizationDetails)
    }
}
