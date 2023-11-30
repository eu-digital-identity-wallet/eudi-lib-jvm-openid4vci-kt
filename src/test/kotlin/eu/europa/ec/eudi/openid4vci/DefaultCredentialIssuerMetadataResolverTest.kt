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

import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.CredentialResponseAsymmetricEncryptionAlgorithmsRequired
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlin.test.*

internal class DefaultCredentialIssuerMetadataResolverTest {

    @Test
    internal fun `fails when metadata cannot be fetched`() = runTest {
        val resolver = resolver(
            RequestMocker(
                requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                responseBuilder = {
                    respond(
                        content = "Not Found",
                        status = HttpStatusCode.NotFound,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
                requestValidator = {
                    assertEquals(
                        credentialIssuerMetadataUrl().value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
            expectSuccessOnly = true,
        )
        assertFailsWith<UnableToFetchCredentialIssuerMetadata> {
            resolver.resolve(credentialIssuerId()).getOrThrow()
        }
    }

    @Test
    internal fun `fails when metadata cannot be parsed`() = runTest {
        val resolver = resolver(
            RequestMocker(
                requestMatcher = match(credentialIssuerMetadataUrl().value.toURI()),
                responseBuilder = jsonResponse("eu/europa/ec/eudi/openid4vci/internal/invalid_credential_issuer_metadata.json"),
                requestValidator = {
                    assertEquals(
                        credentialIssuerMetadataUrl().value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
        )
        assertFailsWith<NonParseableCredentialIssuerMetadata> {
            resolver.resolve(credentialIssuerId()).getOrThrow()
        }
    }

    @Test
    internal fun `fails with unexpected credential issuer id`() = runTest {
        val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
        val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl(credentialIssuerId)
        val resolver = resolver(
            RequestMocker(
                requestMatcher = match(credentialIssuerMetadataUrl.value.toURI()),
                responseBuilder = jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                requestValidator = {
                    assertEquals(
                        credentialIssuerMetadataUrl.value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
        )

        assertFailsWith<InvalidCredentialIssuerId> {
            resolver.resolve(credentialIssuerId).getOrThrow()
        }
    }

    @Test
    internal fun `fails with when response encryption algorithms are not asymmetric`() = runTest {
        val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
        val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl(credentialIssuerId)

        val resolver = resolver(
            RequestMocker(
                requestMatcher = match(credentialIssuerMetadataUrl.value.toURI()),
                responseBuilder = jsonResponse(
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_asymmetric_algs.json",
                ),
                requestValidator = {
                    assertEquals(
                        credentialIssuerMetadataUrl.value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
        )
        assertFailsWith<CredentialResponseAsymmetricEncryptionAlgorithmsRequired> {
            resolver.resolve(credentialIssuerId).getOrThrow()
        }
    }

    @Test
    internal fun `resolution success`() = runTest {
        val credentialIssuerId = credentialIssuerId()
        val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl()

        val resolver = resolver(
            RequestMocker(
                requestMatcher = match(credentialIssuerMetadataUrl.value.toURI()),
                responseBuilder = jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                requestValidator = {
                    assertEquals(
                        credentialIssuerMetadataUrl.value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
        )
        resolver
            .resolve(credentialIssuerId)
            .fold(
                { assertEquals(credentialIssuerMetadata(), it) },
                {
                    assertEquals(
                        IllegalArgumentException("CredentialIssuerMetadata resolution should have succeeded"),
                        it,
                    )
                },
            )
    }
}

private fun resolver(request: RequestMocker, expectSuccessOnly: Boolean = false): CredentialIssuerMetadataResolver =
    CredentialIssuerMetadataResolver(
        ktorHttpClientFactory = mockedKtorHttpClientFactory(request, expectSuccessOnly = expectSuccessOnly),
    )
