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
                    match(authorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/authorization_server_metadata.json"),
                ),
            ) { httpGet ->
                AuthorizationServerMetadataResolver(httpGet = httpGet)
                    .resolve(authorizationServerIssuer())
                    .fold(
                        {
                            // equals not implemented by OIDCProviderMetadata
                            Assertions.assertEquals(authorizationServerMetadata().toJSONObject(), it.toJSONObject())
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
            val metadataUrl = authorizationServerMetadataUrl(issuer)

            mockEngine(
                RequestMocker(
                    match(metadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/authorization_server_metadata.json"),
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
}
