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

import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointClient
import java.time.Clock

internal class RefreshAccessToken(
    private val clock: Clock,
    private val tokenEndpointClient: TokenEndpointClient,
) {

    suspend fun AuthorizedRequest.refreshIfNeeded(): Result<AuthorizedRequest> = runCatching {
        val at = clock.instant()
        when {
            !isAccessTokenExpired(at) -> this
            refreshToken == null -> error("Refresh token was not provided")
            else -> refresh(this)
        }
    }

    private suspend fun refresh(authorizedRequest: AuthorizedRequest): AuthorizedRequest {
        val refreshToken = requireNotNull(authorizedRequest.refreshToken)
        val tokensResponse = tokenEndpointClient.refreshAccessToken(
            refreshToken,
            abcaChallenge = authorizedRequest.abcaChallenge,
            dpopNonce = authorizedRequest.authorizationServerDpopNonce,
        ).getOrThrow()
        return authorizedRequest.withRefreshedAccessToken(
            refreshedAccessToken = tokensResponse.tokens.accessToken,
            newRefreshToken = tokensResponse.tokens.refreshToken,
            at = tokensResponse.tokens.timestamp,
            newAbcaChallenge = tokensResponse.abcaChallenge,
            newAuthorizationServerDpopNonce = tokensResponse.dpopNonce,
        )
    }
}
