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
import eu.europa.ec.eudi.openid4vci.RefreshToken
import eu.europa.ec.eudi.openid4vci.internal.http.TokenResponseTO
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.time.Clock
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AuthorizationExpiresInTest {
    private fun tokenResponseOf(json: String): TokenResponse =
        JsonSupport.decodeFromString<TokenResponseTO.Success>(json).tokensOrFail(Clock.systemUTC())

    @Test
    fun `authorization_expires_in is read as seconds`() {
        val response =
            tokenResponseOf(
                """{ "access_token": "at", "refresh_token": "rt", "authorization_expires_in": 2592000 }""",
            )
        assertEquals(RefreshToken("rt"), response.refreshToken)
        assertEquals(Duration.ofSeconds(2592000), response.authorizationExpiresIn)
    }

    @Test
    fun `missing authorization_expires_in leaves it null`() {
        val response = tokenResponseOf("""{ "access_token": "at", "refresh_token": "rt" }""")
        assertNull(response.authorizationExpiresIn)
    }

    @Test
    fun `authorized request keeps authorization expiry when the access token is refreshed`() {
        val issuedAt = Instant.parse("2026-01-01T00:00:00Z")
        val original =
            AuthorizedRequest(
                accessToken = AccessToken.Bearer("at", Duration.ofMinutes(1)),
                refreshToken = RefreshToken("rt"),
                credentialIdentifiers = emptyMap(),
                timestamp = issuedAt,
                authorizationServerDpopNonce = null,
                resourceServerDpopNonce = null,
                grant = Grant.AuthorizationCode,
                authorizationExpiresIn = Duration.ofSeconds(1000),
            )

        val refreshed =
            original.withRefreshedAccessToken(
                refreshedAccessToken = AccessToken.Bearer("at2", Duration.ofMinutes(1)),
                newRefreshToken = RefreshToken("rt2"),
                at = issuedAt.plusSeconds(60),
                newAuthorizationServerDpopNonce = null,
            )

        assertEquals(RefreshToken("rt2"), refreshed.refreshToken)
        assertEquals(Duration.ofSeconds(1000), refreshed.authorizationExpiresIn)
    }

    @Test
    fun `authorized request survives java serialization with its authorization expiry`() {
        val original =
            AuthorizedRequest(
                accessToken = AccessToken.Bearer("at", Duration.ofMinutes(1)),
                refreshToken = RefreshToken("rt"),
                credentialIdentifiers = emptyMap(),
                timestamp = Instant.parse("2026-01-01T00:00:00Z"),
                authorizationServerDpopNonce = null,
                resourceServerDpopNonce = null,
                grant = Grant.PreAuthorizedCodeGrant,
                authorizationExpiresIn = Duration.ofSeconds(1000),
            )
        val bytes = ByteArrayOutputStream().also { ObjectOutputStream(it).use { out -> out.writeObject(original) } }.toByteArray()
        val restored = ObjectInputStream(ByteArrayInputStream(bytes)).use { it.readObject() as AuthorizedRequest }
        assertEquals(original, restored)
    }
}
