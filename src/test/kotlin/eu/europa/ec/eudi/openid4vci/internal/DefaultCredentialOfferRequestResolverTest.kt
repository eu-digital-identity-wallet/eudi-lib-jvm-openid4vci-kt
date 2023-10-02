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
import eu.europa.ec.eudi.openid4vci.OfferedCredential.ScopedCredential
import eu.europa.ec.eudi.openid4vci.OfferedCredential.UnscopedCredential.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.OfferedCredential.UnscopedCredential.W3CVerifiableCredential
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialOfferRequestResolver
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.http.client.utils.URIBuilder
import org.junit.jupiter.api.Assertions
import java.io.File
import kotlin.test.Test

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

            val expected = CredentialOffer(
                CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                listOf(
                    ScopedCredential("UniversityDegree_JWT"),
                    MsoMdocCredential("org.iso.18013.5.1.mDL"),
                ),
                Grants.Both(
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                    Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
                ),
            )

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.assertEquals(expected, it) },
                    { Assertions.fail("Credential Offer resolution should have succeeded", it) },
                )
        }
    }

    @Test
    fun `resolve success with mos_mdoc`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

            val expected = CredentialOffer(
                CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                listOf(
                    MsoMdocCredential("org.iso.18013.5.1.mDL"),
                ),
                Grants.Both(
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                    Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
                ),
            )

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.assertEquals(expected, it) },
                    { Assertions.fail("Credential Offer resolution should have succeeded", it) },
                )
        }
    }

    @Test
    internal fun `resolve success with jwt_vc_json`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

            val expected = CredentialOffer(
                CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                listOf(
                    W3CVerifiableCredential.SignedJwt(
                        JsonObject(
                            mapOf(
                                "type" to JsonArray(
                                    listOf(
                                        JsonPrimitive("VerifiableCredential"),
                                        JsonPrimitive("UniversityDegreeCredential"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                Grants.Both(
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                    Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
                ),
            )

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.assertEquals(expected, it) },
                    { Assertions.fail("Credential Offer resolution should have succeeded", it) },
                )
        }
    }

    @Test
    internal fun `resolve success with ldp_vc`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

            val expected = CredentialOffer(
                CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                listOf(
                    W3CVerifiableCredential.JsonLdDataIntegrity(
                        JsonObject(
                            mapOf(
                                "@context" to JsonArray(
                                    listOf(
                                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                                        JsonPrimitive("https://www.w3.org/2018/credentials/examples/v1"),
                                    ),
                                ),
                                "type" to JsonArray(
                                    listOf(
                                        JsonPrimitive("VerifiableCredential"),
                                        JsonPrimitive("UniversityDegreeCredential"),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                Grants.Both(
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                    Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
                ),
            )

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.assertEquals(expected, it) },
                    { Assertions.fail("Credential Offer resolution should have succeeded", it) },
                )
        }
    }

    @Test
    internal fun `resolve failure with unknown credential format`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_unknown_format.json")

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.fail("Credential Offer resolution should have failed") },
                    {
                        val exception = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                        Assertions.assertInstanceOf(
                            CredentialOfferRequestValidationError.InvalidCredentials::class.java,
                            exception.error,
                        )
                    },
                )
        }
    }

    @Test
    internal fun `resolve failure with blank issuer_state in grant`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_issuer_state.json")

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.fail("Credential Offer resolution should have failed") },
                    {
                        val exception = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                        Assertions.assertInstanceOf(
                            CredentialOfferRequestValidationError.InvalidGrants::class.java,
                            exception.error,
                        )
                    },
                )
        }
    }

    @Test
    internal fun `resolve failure with blank pre-authorized_code in grant`() = runBlocking {
        mockCredentialIssuerMetadataRequest { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_pre_authorized_code.json")

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    { Assertions.fail("Credential Offer resolution should have failed") },
                    {
                        val exception = Assertions.assertInstanceOf(CredentialOfferRequestException::class.java, it)
                        Assertions.assertInstanceOf(
                            CredentialOfferRequestValidationError.InvalidGrants::class.java,
                            exception.error,
                        )
                    },
                )
        }
    }

    @Test
    internal fun `resolve success with credential_offer_uri`() = runBlocking {
        val credentialOffer = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

        val expected = CredentialOffer(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            listOf(
                ScopedCredential("UniversityDegree_JWT"),
                MsoMdocCredential("org.iso.18013.5.1.mDL"),
            ),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
            ),
        )

        val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()
        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
            .build()

        val mockEngine = MockEngine {
            when (it.url.toURI().toString()) {
                credentialOfferUri.value.toString() -> respond(
                    content = credentialOffer,
                    headers = headersOf(
                        HttpHeaders.ContentType to listOf("application/json"),
                    ),
                )

                "https://credential-issuer.example.com/.well-known/openid-credential-issuer" ->
                    respond(
                        content = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )

                else -> Assertions.fail("Did not expect call to ${it.url.toURI()}")
            }
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json()
            }
        }

        DefaultCredentialOfferRequestResolver(Dispatchers.IO) {
            runCatching {
                httpClient.get(it.toURI().toURL()).bodyAsText()
            }
        }
            .resolve(credentialEndpointUrl.toString())
            .fold(
                {
                    Assertions.assertEquals(expected, it)
                    Assertions.assertEquals(
                        2,
                        mockEngine.requestHistory.size,
                        "Expected exactly 2 requests during Credential Offer resolution",
                    )
                },
                { Assertions.fail("Credential Offer resolution should have succeeded", it) },
            )
    }

    companion object {
        private fun getResourceAsText(resource: String): String =
            File(ClassLoader.getSystemResource(resource).path).readText()

        private suspend fun mockCredentialIssuerMetadataRequest(action: suspend (HttpGet<String>) -> Unit) {
            val mockEngine = MockEngine {
                if (it.url
                        .toURI()
                        .toString() == "https://credential-issuer.example.com/.well-known/openid-credential-issuer"
                ) {
                    respond(
                        content = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                } else {
                    Assertions.fail("Unexpected HTTP call to '${it.url}'")
                }
            }
            val httpClient = HttpClient(mockEngine) {
                install(ContentNegotiation) {
                    json()
                }
            }
            val httpGet = HttpGet {
                runCatching {
                    httpClient.get(it).bodyAsText()
                }
            }

            action(httpGet)

            Assertions.assertEquals(
                1,
                mockEngine.requestHistory.size,
                "Expected Credential Issuer Metadata to have been fetched",
            )
        }
    }
}
