package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationServerClient
import java.time.Clock


internal class RefreshAccessToken(
    private val clock: Clock,
    private val authorizationServerClient: AuthorizationServerClient
) {

    suspend fun refreshIfNeeded(
        authorizedRequest: AuthorizedRequest
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
            at = tokenResponse.timestamp
        )
    }

}