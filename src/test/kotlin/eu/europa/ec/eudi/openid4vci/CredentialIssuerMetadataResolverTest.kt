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
import eu.europa.ec.eudi.openid4vci.internal.CredentialIssuerMetadataResolver
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

internal class CredentialIssuerMetadataResolverTest {

    @Test
    internal fun `fails when metadata cannot be fetched`() = runTest {
        val resolve = mockResolver(
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
                        SampleIssuer.WellKnownUrl.value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
            expectSuccessOnly = true,
        )

        assertFailsWith<UnableToFetchCredentialIssuerMetadata> { resolve(SampleIssuer.Id) }
    }

    @Test
    internal fun `fails when metadata cannot be parsed`() = runTest {
        val resolve = mockResolver(
            credentialIssuerMetaDataHandler(
                SampleIssuer.Id,
                "eu/europa/ec/eudi/openid4vci/internal/invalid_credential_issuer_metadata.json",
            ),
        )
        assertFailsWith<NonParseableCredentialIssuerMetadata> { resolve(SampleIssuer.Id) }
    }

    @Test
    internal fun `fails with unexpected credential issuer id`() = runTest {
        val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
        val resolve = mockResolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )
        assertFailsWith<InvalidCredentialIssuerId> { resolve(credentialIssuerId) }
    }

    @Test
    internal fun `fails with when response encryption algorithms are not asymmetric`() = runTest {
        val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
        val resolve = mockResolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_asymmetric_algs.json",
            ),
        )
        assertFailsWith<CredentialResponseAsymmetricEncryptionAlgorithmsRequired> {
            resolve(credentialIssuerId)
        }
    }

    @Test
    internal fun `resolution success`() = runTest {
        val credentialIssuerId = SampleIssuer.Id
        val resolve = mockResolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )
        val metaData = assertDoesNotThrow { resolve(credentialIssuerId) }
        assertEquals(credentialIssuerMetadata(), metaData)
    }
}

private fun mockResolver(
    request: RequestMocker,
    expectSuccessOnly: Boolean = false,
): suspend (CredentialIssuerId) -> CredentialIssuerMetadata = { issuer ->
    mockedKtorHttpClientFactory(request, expectSuccessOnly = expectSuccessOnly).invoke().use { httpClient ->
        with(CredentialIssuerMetadataResolver) {
            httpClient.resolve(issuer)
        }
    }
}
