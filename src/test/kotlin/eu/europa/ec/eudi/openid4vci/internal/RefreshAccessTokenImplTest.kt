/*
 * Copyright (c) 2023-2026 European Commission
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

import eu.europa.ec.eudi.openid4vci.AccessToken
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.Grant
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfiguration
import eu.europa.ec.eudi.openid4vci.RefreshToken
import eu.europa.ec.eudi.openid4vci.SampleIssuer
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointClient
import eu.europa.ec.eudi.openid4vci.mockedHttpClient
import eu.europa.ec.eudi.openid4vci.oauthAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.tokenPostMocker
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.request.forms.FormDataContent
import io.ktor.http.HttpMethod
import kotlinx.coroutines.test.runTest
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.fail
import kotlin.time.Duration.Companion.minutes
import kotlin.time.toJavaDuration

class RefreshAccessTokenImplTest {
    private val clock = Clock.systemDefaultZone()

    @Test
    fun `fails when no refresh token is present`() = runTest {
        val engine = MockEngine { fail("no http calls were expected") }
        val tokenEndpointClient = tokenEndpointClient(HttpClient(engine))
        val refreshAccessToken = RefreshAccessTokenImpl(tokenEndpointClient)

        val authorizedRequest = authorizedRequest(
            accessTokenIssuedAt = clock.instant(),
            accessTokenExpiresIn = 0.minutes.toJavaDuration(),
            refreshToken = null,
        )

        with(refreshAccessToken) {
            val exception = assertFailsWith<IllegalStateException> { authorizedRequest.refresh().getOrThrow() }
            assertEquals("Refresh token was not provided", exception.message)
        }
    }

    @Test
    fun `refreshes when manually invoked`() = runTest {
        val httpClient = mockedHttpClient(
            tokenPostMocker {
                assertEquals(HttpMethod.Post, it.method)
                val formData = assertIs<FormDataContent>(it.body).formData
                assertEquals("refresh_token", formData["grant_type"])
                assertEquals("Refresh", formData["refresh_token"])
            },
        )
        val tokenEndpointClient = tokenEndpointClient(httpClient)
        val refreshAccessToken = RefreshAccessTokenImpl(tokenEndpointClient)

        val authorizedRequest = authorizedRequest(
            accessTokenIssuedAt = clock.instant(),
            accessTokenExpiresIn = 10.minutes.toJavaDuration(),
            refreshToken = RefreshToken("Refresh"),
        )

        val refreshedAuthorizedRequest = with(refreshAccessToken) {
            authorizedRequest.refresh().getOrThrow()
        }
        assertNotEquals(authorizedRequest, refreshedAuthorizedRequest)
        assertNotEquals(authorizedRequest.accessToken, refreshedAuthorizedRequest.accessToken)
        assertEquals(authorizedRequest.refreshToken, refreshedAuthorizedRequest.refreshToken)
    }
}

private fun authorizedRequest(
    accessTokenIssuedAt: Instant,
    accessTokenExpiresIn: Duration,
    refreshToken: RefreshToken?,
) = AuthorizedRequest(
    accessToken = AccessToken.Bearer("Token", accessTokenExpiresIn),
    refreshToken = refreshToken,
    credentialIdentifiers = emptyMap(),
    timestamp = accessTokenIssuedAt,
    authorizationServerDpopNonce = null,
    resourceServerDpopNonce = null,
    grant = Grant.AuthorizationCode,
)

private fun tokenEndpointClient(httpClient: HttpClient) = TokenEndpointClient(
    SampleIssuer.Id,
    oauthAuthorizationServerMetadata(),
    OpenId4VCIConfiguration,
    null,
    null,
    httpClient,
)
