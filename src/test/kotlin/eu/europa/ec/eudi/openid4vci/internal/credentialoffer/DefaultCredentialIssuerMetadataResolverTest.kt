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
package eu.europa.ec.eudi.openid4vci.internal.credentialoffer

import eu.europa.ec.eudi.openid4vci.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

internal class DefaultCredentialIssuerMetadataResolverTest {

    @Test
    internal fun `fails when metadata cannot be fetched`() {
        runTest {
            mockEngine(
                verifier = {
                    assertEquals(1, it.size)
                    assertEquals(
                        credentialIssuerMetadataUrl().value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId())
                    .fold(
                        { fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            assertIs<CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata>(it)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `fails when metadata cannot be parsed`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/invalid_credential_issuer_metadata.json"),
                ),
                verifier = {
                    assertEquals(1, it.size)
                    assertEquals(
                        credentialIssuerMetadataUrl().value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId())
                    .fold(
                        { fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            assertIs<CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata>(it)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `fails with unexpected credential issuer id`() {
        runTest {
            val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
            val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl(credentialIssuerId)
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                verifier = {
                    assertEquals(1, it.size)
                    assertEquals(
                        credentialIssuerMetadataUrl.value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId)
                    .fold(
                        { fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            assertIs<CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId>(it)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `fails with when response encryption algorithms are not asymmetric`() {
        runTest {
            val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
            val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl(credentialIssuerId)
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_asymmetric_algs.json"),
                ),
                verifier = {
                    assertEquals(1, it.size)
                    assertEquals(
                        credentialIssuerMetadataUrl.value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
                    .resolve(credentialIssuerId)
                    .fold(
                        { fail("CredentialIssuerMetadata resolution should have failed") },
                        {
                            assertIs<CredentialIssuerMetadataValidationError.CredentialResponseAsymmetricEncryptionAlgorithmsRequired>(it)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `resolution success`() {
        runTest {
            val credentialIssuerId = credentialIssuerId()
            val credentialIssuerMetadataUrl = credentialIssuerMetadataUrl()

            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                verifier = {
                    assertEquals(1, it.size)
                    assertEquals(
                        credentialIssuerMetadataUrl.value,
                        it[0].url.toURI(),
                    )
                },
            ) { httpGet ->
                CredentialIssuerMetadataResolver(httpGet = httpGet)
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
    }
}
