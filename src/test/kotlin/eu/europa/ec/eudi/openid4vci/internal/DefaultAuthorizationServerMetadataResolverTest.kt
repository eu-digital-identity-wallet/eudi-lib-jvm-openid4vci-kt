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

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import kotlin.test.Test

internal class DefaultAuthorizationServerMetadataResolverTest {

    @Test
    internal fun `resolution success`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
            ) { httpGet ->
                AuthorizationServerMetadataResolver(httpGet = httpGet)
                    .resolve(authorizationServerIssuer())
                    .fold(
                        {
                            Assertions.assertInstanceOf(OIDCProviderMetadata::class.java, it)
                            // equals not implemented by OIDCProviderMetadata
                            Assertions.assertEquals(oidcAuthorizationServerMetadata().toJSONObject(), it.toJSONObject())
                        },
                        { Assertions.fail("Authorization Server metadata resolution should have succeeded", it) },
                    )
            }
        }
    }

    @Test
    internal fun `fails when issuer does not match`() {
        runBlocking {
            val issuer = HttpsUrl("https://keycloak.netcompany.com/realms/pid-issuer-realm").getOrThrow()
            val metadataUrl = oidcAuthorizationServerMetadataUrl(issuer)

            mockEngine(
                RequestMocker(
                    match(metadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
            ) { httpGet ->
                AuthorizationServerMetadataResolver(httpGet = httpGet)
                    .resolve(issuer)
                    .fold(
                        { Assertions.fail("Authorization Server metadata resolution should have failed") },
                        {
                            val exception = Assertions.assertInstanceOf(
                                AuthorizationServerMetadataResolutionException::class.java,
                                it,
                            )
                            val cause =
                                Assertions.assertInstanceOf(IllegalArgumentException::class.java, exception.cause)
                            Assertions.assertEquals("issuer does not match the expected value", cause.message)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `falls back to oauth server metadata`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match(oauthAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(2, it.size) },
            ) { httpGet ->
                AuthorizationServerMetadataResolver(httpGet = httpGet)
                    .resolve(authorizationServerIssuer())
                    .fold(
                        {
                            Assertions.assertInstanceOf(AuthorizationServerMetadata::class.java, it)
                            // equals not implemented by AuthorizationServerMetadata
                            Assertions.assertEquals(
                                oauthAuthorizationServerMetadata().toJSONObject(),
                                it.toJSONObject(),
                            )
                        },
                        { Assertions.fail("Authorization Server metadata resolution should have succeeded", it) },
                    )
            }
        }
    }
}
