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
    private val issuerMetadata: CredentialIssuerMetadata,
    authorizationServerMetadata: CIAuthorizationServerMetadata,
    config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizeIssuance {

    private val authorizer: IssuanceAuthorizer =
        IssuanceAuthorizer(authorizationServerMetadata, config, ktorHttpClientFactory)

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialIdentifier>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> = runCatching {
        val (codeVerifier, parAuthorizationUrl) = run {
            val scopes = credentials.mapNotNull { credentialId ->
                credentialSupportedById(credentialId).scope?.let { Scope(it) }
            }
            val state = State().value
            authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()
        }
        UnauthorizedRequest.ParRequested(parAuthorizationUrl, codeVerifier)
    }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved = UnauthorizedRequest.AuthorizationCodeRetrieved(authorizationCode, pkceVerifier)

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
        authorizer.requestAccessTokenAuthFlow(authorizationCode.code, pkceVerifier.codeVerifier)
            .map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }

    override suspend fun authorizeWithPreAuthorizationCode(
        preAuthorizationCode: PreAuthorizationCode,
    ): Result<AuthorizedRequest> =
        authorizer.requestAccessTokenPreAuthFlow(
            preAuthorizationCode.preAuthorizedCode,
            preAuthorizationCode.pin,
        ).map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }

    private fun credentialSupportedById(credentialId: CredentialIdentifier): CredentialSupported {
        val credentialSupported = issuerMetadata.credentialsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }
}
