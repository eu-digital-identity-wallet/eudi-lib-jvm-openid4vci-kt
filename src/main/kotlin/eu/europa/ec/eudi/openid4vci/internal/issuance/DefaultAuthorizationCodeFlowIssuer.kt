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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import eu.europa.ec.eudi.openid4vci.*
import java.time.Instant

class DefaultAuthorizationCodeFlowIssuer(
    val authorizer: IssuanceAuthorizer,
) : AuthorizationCodeFlowIssuer {

    override suspend fun placePushedAuthorizationRequest(
        credentials: List<OfferedCredential>,
        issuerState: String?,
    ): Result<AuthCodeFlowIssuance.ParRequested> =
        runCatching {
            // Get scoped credentials only
            val scopes = credentials.filterIsInstance<OfferedCredential.ScopedCredential>()
                .map(OfferedCredential.ScopedCredential::scope)

            // Place PAR
            val (codeVerifier, getAuthorizationCodeUrl) =
                authorizer.submitPushedAuthorizationRequest(scopes, issuerState).getOrThrow()

            // Transition state
            AuthCodeFlowIssuance.ParRequested(
                getAuthorizationCodeURL = getAuthorizationCodeUrl,
                pkceVerifier = codeVerifier,
            )
        }

    override suspend fun AuthCodeFlowIssuance.ParRequested.authorize(
        authorizationCode: String,
    ): Result<AuthCodeFlowIssuance.Authorized> =
        Result.success(
            AuthCodeFlowIssuance.Authorized(
                authorizationCode = IssuanceAuthorization.AuthorizationCode(authorizationCode),
                pkceVerifier = this.pkceVerifier,
            ),
        )

    override suspend fun AuthCodeFlowIssuance.Authorized.placeAccessTokenRequest(): Result<AuthCodeFlowIssuance.AccessTokenRetrieved> =
        runCatching {
            val accessToken =
                authorizer.requestAccessTokenAuthFlow(
                    this.authorizationCode.authorizationCode,
                    this.pkceVerifier.codeVerifier,
                ).getOrThrow()

            AuthCodeFlowIssuance.AccessTokenRetrieved(
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun AuthCodeFlowIssuance.AccessTokenRetrieved.issueCredential(): Result<AuthCodeFlowIssuance.Issued> =
        Result.success(
            AuthCodeFlowIssuance.Issued(
                issuedAt = Instant.now(), // Will be the issuer's issuance date
                certificate = IssuedCertificate(
                    format = "mso_mdoc",
                    content = "TODO-IssuedCertificate.content",
                ),
            ),
        )
}
