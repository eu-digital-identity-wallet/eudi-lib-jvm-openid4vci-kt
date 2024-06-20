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
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationServerClient
import java.time.Clock

internal class RefreshAccessToken(
    private val clock: Clock,
    private val authorizationServerClient: AuthorizationServerClient,
) {

    suspend fun refreshIfNeeded(
        authorizedRequest: AuthorizedRequest,
    ): Result<AuthorizedRequest> = runCatching {
        val at = clock.instant()
        when {
            !authorizedRequest.isAccessTokenExpired(at) -> authorizedRequest
            authorizedRequest.isRefreshTokenExpiredOrMissing(at) -> error("Refresh token is expired or missing")
            else -> {
                checkNotNull(authorizedRequest.refreshToken)
                refresh(authorizedRequest)
            }
        }
    }

    private suspend fun refresh(authorizedRequest: AuthorizedRequest): AuthorizedRequest {
        val refreshToken = requireNotNull(authorizedRequest.refreshToken)
        val tokenResponse = authorizationServerClient.refreshAccessToken(refreshToken).getOrThrow()
        return authorizedRequest.withRefreshedAccessToken(
            refreshedAccessToken = tokenResponse.accessToken,
            newRefreshToken = tokenResponse.refreshToken,
            at = tokenResponse.timestamp,
        )
    }
}
