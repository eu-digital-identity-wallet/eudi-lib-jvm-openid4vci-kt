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
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataResolver
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions
import kotlin.test.Test

internal class DefaultCredentialIssuerMetadataResolverTest {

    @Test
    internal fun `fails when metadata cannot be fetched`() {
        runBlocking {
            mockEngine(
                verifier = {
                    Assertions.assertEquals(1, it.size)
                    Assertions.assertEquals(
                        credentialIssuerMetadataUrl().value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId())
                    .fold(
                        { Assertions.fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            val exception =
                                Assertions.assertInstanceOf(CredentialIssuerMetadataException::class.java, it)
                            Assertions.assertInstanceOf(
                                CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata::class.java,
                                exception.error,
                            )
                        },
                    )
            }
        }
    }

    @Test
    internal fun `fails when metadata cannot be parsed`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/invalid_credential_issuer_metadata.json"),
                ),
                verifier = {
                    Assertions.assertEquals(1, it.size)
                    Assertions.assertEquals(
                        credentialIssuerMetadataUrl().value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId())
                    .fold(
                        { Assertions.fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            val exception =
                                Assertions.assertInstanceOf(CredentialIssuerMetadataException::class.java, it)
                            Assertions.assertInstanceOf(
                                CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata::class.java,
                                exception.error,
                            )
                        },
                    )
            }
        }
    }

    @Test
    internal fun `fails with unexpected credential issuer id`() {
        runBlocking {
            val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
            val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl(credentialIssuerId)
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = {
                    Assertions.assertEquals(1, it.size)
                    Assertions.assertEquals(
                        credentialIssuerMetadataUrl.value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId)
                    .fold(
                        { Assertions.fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            val exception =
                                Assertions.assertInstanceOf(CredentialIssuerMetadataException::class.java, it)
                            Assertions.assertInstanceOf(
                                CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId::class.java,
                                exception.error,
                            )
                        },
                    )
            }
        }
    }

    @Test
    internal fun `resolution success`() {
        runBlocking {
            val credentialIssuerId = credentialIssuerId()
            val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl()

            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = {
                    Assertions.assertEquals(1, it.size)
                    Assertions.assertEquals(
                        credentialIssuerMetadataUrl.value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId)
                    .fold(
                        { Assertions.assertEquals(credentialIssuerMetadata(), it) },
                        { Assertions.assertEquals("CredentialIssuerMetadata resolution should have succeeded", it) },
                    )
            }
        }
    }
}
