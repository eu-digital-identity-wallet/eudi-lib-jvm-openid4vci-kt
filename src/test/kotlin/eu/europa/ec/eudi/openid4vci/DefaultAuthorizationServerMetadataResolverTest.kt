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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import io.ktor.client.plugins.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

internal class DefaultAuthorizationServerMetadataResolverTest {

    @Test
    internal fun `resolution success fallback to compliant oauth2 well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create(
                        "https://keycloak-eudi.netcompany-intrasoft.com/.well-known/oauth-authorization-server/realms/pid-issuer-realm",
                    ),
                ),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata.json"),
            ),
        )
        val metadata = resolver.resolve(issuer).getOrThrow()
        assertIs<AuthorizationServerMetadata>(metadata)
        // equals not implemented by AuthorizationServerMetadata
        assertEquals(oauthAuthorizationServerMetadata().toJSONObject(), metadata.toJSONObject())
    }

    @Test
    internal fun `fails when issuer does not match`() = runTest {
        val issuer = HttpsUrl("https://keycloak.netcompany.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create("https://keycloak.netcompany.com/.well-known/oauth-authorization-server/realms/pid-issuer-realm"),
                ),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata.json"),
            ),
        )
        val ex = assertFailsWith<AuthorizationServerMetadataResolutionException> {
            resolver.resolve(issuer).getOrThrow()
        }
        val cause = assertIs<IllegalArgumentException>(ex.cause)
        assertEquals("issuer does not match the expected value", cause.message)
    }

    @Test
    internal fun `fails when none of the possible urls returns the metadata`() = runTest {
        val issuer = HttpsUrl("https://keycloak.netcompany.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = AuthorizationServerMetadataResolver(mockedKtorHttpClientFactory(expectSuccessOnly = true))
        val error = assertFailsWith<AuthorizationServerMetadataResolutionException> {
            resolver.resolve(issuer).getOrThrow()
        }
        val cause = assertIs<ClientRequestException>(error.cause)
        assertEquals(HttpStatusCode.NotFound, cause.response.status)

        // Verify the last URL that was tried, is the common lookup for oauth2 authorization server metadata.
        assertEquals(
            "https://keycloak.netcompany.com/.well-known/oauth-authorization-server/realms/pid-issuer-realm",
            cause.response.request.url.toString(),
        )
    }
}

private fun mockResolver(mocker: RequestMocker) =
    AuthorizationServerMetadataResolver(mockedKtorHttpClientFactory(mocker))
