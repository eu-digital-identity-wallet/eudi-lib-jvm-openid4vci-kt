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
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

internal class DefaultAuthorizationServerMetadataResolverTest {

    @Test
    internal fun `resolution success with compliant oidc well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create("https://keycloak-eudi.netcompany-intrasoft.com/.well-known/openid-configuration/realms/pid-issuer-realm"),
                ),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val meta = resolver.resolve(issuer).getOrThrow()
        assertIs<OIDCProviderMetadata>(meta)
        // equals not implemented by OIDCProviderMetadata
        assertEquals(oidcAuthorizationServerMetadata().toJSONObject(), meta.toJSONObject())
    }

    @Test
    internal fun `resolution success with non-compliant oidc well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm/.well-known/openid-configuration"),
                ),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val meta = resolver.resolve(issuer).getOrThrow()
        assertIs<OIDCProviderMetadata>(meta)
        // equals not implemented by OIDCProviderMetadata
        assertEquals(oidcAuthorizationServerMetadata().toJSONObject(), meta.toJSONObject())
    }

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
    internal fun `resolution success fallback to non-compliant oauth2 well-known url`() = runTest {
        val issuer = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()
        val resolver = mockResolver(
            RequestMocker(
                match(
                    URI.create(
                        "https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm/.well-known/oauth-authorization-server",
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
                    URI.create("https://keycloak.netcompany.com/.well-known/openid-configuration/realms/pid-issuer-realm"),
                ),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val ex = assertFailsWith<AuthorizationServerMetadataResolutionException> {
            resolver.resolve(issuer).getOrThrow()
        }
        val cause = assertIs<IllegalArgumentException>(ex.cause)
        assertEquals("issuer does not match the expected value", cause.message)
    }
}

private fun mockResolver(mocker: RequestMocker) =
    AuthorizationServerMetadataResolver(mockedKtorHttpClientFactory(mocker))
