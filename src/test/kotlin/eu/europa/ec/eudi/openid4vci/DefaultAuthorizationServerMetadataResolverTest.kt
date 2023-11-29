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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

internal class DefaultAuthorizationServerMetadataResolverTest {

    @Test
    internal fun `resolution success`() = runTest {
        val resolver = mockResolver(
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val meta = resolver.resolve(authorizationServerIssuer()).getOrThrow()
        assertIs<OIDCProviderMetadata>(meta)
        // equals not implemented by OIDCProviderMetadata
        assertEquals(oidcAuthorizationServerMetadata().toJSONObject(), meta.toJSONObject())
    }

    @Test
    internal fun `fails when issuer does not match`() = runTest {
        val issuer = HttpsUrl("https://keycloak.netcompany.com/realms/pid-issuer-realm").getOrThrow()
        val metadataUrl = oidcAuthorizationServerMetadataUrl(issuer)
        val resolver = mockResolver(
            RequestMocker(
                match(metadataUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val cause = resolver.resolve(issuer).fold(
            onSuccess = { fail("Authorization Server metadata resolution should have failed") },
            onFailure = causeIs<IllegalArgumentException>(),
        )
        assertEquals("issuer does not match the expected value", cause.message)
    }

    @Test
    internal fun `falls back to oauth server metadata`() = runTest {
        val resolver = mockResolver(
            RequestMocker(
                match(oauthAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata.json"),
            ),
        )

        val metadata = resolver.resolve(authorizationServerIssuer()).getOrThrow()
        assertIs<AuthorizationServerMetadata>(metadata)
        // equals not implemented by AuthorizationServerMetadata
        assertEquals(oauthAuthorizationServerMetadata().toJSONObject(), metadata.toJSONObject())
    }

    private inline fun <reified T : Throwable> causeIs(): (Throwable) -> T = { t ->
        val error = assertIs<AuthorizationServerMetadataResolutionException>(t)
        assertIs<T>(error.cause)
    }
}

private fun mockResolver(mocker: RequestMocker): AuthorizationServerMetadataResolver =
    AuthorizationServerMetadataResolver(
        ktorHttpClientFactory =
            mockedKtorHttpClientFactory(mocker),
    )
