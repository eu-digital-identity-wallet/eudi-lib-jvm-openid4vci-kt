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

internal class AuthorizeIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizeIssuance {

    private val authorizer: IssuanceAuthorizer =
        IssuanceAuthorizer(credentialOffer.authorizationServerMetadata, config, ktorHttpClientFactory)
    override suspend fun prepareAuthorizationRequest(): Result<AuthorizationRequestPrepared> = runCatching {
        val scopes = credentialOffer.credentials.mapNotNull { credentialId ->
            credentialSupportedById(credentialId).scope?.let { Scope(it) }
        }
        val state = State().value
        val issuerState = when (credentialOffer.grants) {
            is Grants.AuthorizationCode -> credentialOffer.grants.issuerState
            is Grants.Both -> credentialOffer.grants.authorizationCode.issuerState
            else -> null
        }

        val authorizationServerSupportsPar = credentialOffer.authorizationServerMetadata.pushedAuthorizationRequestEndpointURI != null
        val (codeVerifier, authorizationCodeUrl) = when (authorizationServerSupportsPar) {
            true -> authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()
            false -> authorizer.authorizationRequestUrl(scopes, state, issuerState).getOrThrow()
        }
        AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier)
    }

    private fun credentialSupportedById(credentialId: CredentialIdentifier): CredentialSupported {
        val credentialSupported = credentialOffer.credentialIssuerMetadata.credentialsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    override suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): Result<AuthorizedRequest> = authorizer.requestAccessTokenAuthFlow(authorizationCode.code, pkceVerifier.codeVerifier)
        .map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }

    override suspend fun authorizeWithPreAuthorizationCode(pin: String?): Result<AuthorizedRequest> = runCatching {
        val offeredGrants = credentialOffer.grants
        require(offeredGrants != null) { "Grant not specified in credential offer." }
        val preAuthorizedCode = when (offeredGrants) {
            is Grants.PreAuthorizedCode -> offeredGrants
            is Grants.Both -> offeredGrants.preAuthorizedCode
            is Grants.AuthorizationCode -> error("Pre-authorized code grant expected")
        }
        if (preAuthorizedCode.pinRequired && pin.isNullOrEmpty()) {
            error("Issuer's grant is pre-authorization code with pin required but no pin passed")
        }
        return authorizer.requestAccessTokenPreAuthFlow(preAuthorizedCode.preAuthorizedCode, pin)
            .map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }
    }
}
