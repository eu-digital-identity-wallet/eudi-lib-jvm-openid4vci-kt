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
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialOfferRequestResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.http.client.utils.URIBuilder
import org.junit.jupiter.api.Assertions
import kotlin.test.Test

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

                val expected = CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
                            universityDegreeJwt().credentialDefinition,
                            "UniversityDegree_JWT",
                        ),
                        OfferedCredential.MsoMdocCredential("org.iso.18013.5.1.mDL"),
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
    }

    @Test
    fun `resolve success with mos_mdoc`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

                val expected = CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.MsoMdocCredential("org.iso.18013.5.1.mDL"),
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
    }

    @Test
    internal fun `resolve success with jwt_vc_json`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

                val expected = CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
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
    }

    @Test
    internal fun `resolve success with ldp_vc`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

                val expected = CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.JsonLdDataIntegrity(
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
    }

    @Test
    internal fun `resolve failure with unknown credential format`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
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
    }

    @Test
    internal fun `resolve failure with blank issuer_state in grant`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
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
    }

    @Test
    internal fun `resolve failure with blank pre-authorized_code in grant`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
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
    }

    @Test
    internal fun `resolve success with credential_offer_uri`() {
        runBlocking {
            val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()

            mockEngine(
                RequestMocker(
                    match("https://credential-issuer.example.com/.well-known/openid-credential-issuer"),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                RequestMocker(
                    match(credentialOfferUri.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json"),
                ),
                verifier = { Assertions.assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
                    .build()

                val expected = CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
                            universityDegreeJwt().credentialDefinition,
                            "UniversityDegree_JWT",
                        ),
                        OfferedCredential.MsoMdocCredential("org.iso.18013.5.1.mDL"),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
                    ),
                )

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        { Assertions.assertEquals(expected, it) },
                        { Assertions.fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }

    companion object {

        /**
         * Gets the 'UniversityDegree_JWT' scoped credential used throughout these tests.
         */
        private fun universityDegreeJwt() =
            CredentialSupportedObject.W3CVerifiableCredentialSignedJwtCredentialSupportedObject(
                "jwt_vc_json",
                "UniversityDegree_JWT",
                listOf("did:example"),
                listOf("ES256K"),
                listOf("jwt"),
                listOf(
                    DisplayObject(
                        "University Credential",
                        "en-US",
                        DisplayObject.LogoObject(
                            "https://exampleuniversity.com/public/logo.png",
                            "a square logo of a university",
                        ),
                        null,
                        "#12107c",
                        "#FFFFFF",
                    ),
                ),
                JsonObject(
                    mapOf(
                        "type" to JsonArray(
                            listOf(
                                JsonPrimitive("VerifiableCredential"),
                                JsonPrimitive("UniversityDegreeCredential"),
                            ),
                        ),
                        "credentialSubject" to JsonObject(
                            mapOf(
                                "given_name" to JsonObject(
                                    mapOf(
                                        "display" to JsonArray(
                                            listOf(
                                                JsonObject(
                                                    mapOf(
                                                        "name" to JsonPrimitive("Given Name"),
                                                        "locale" to JsonPrimitive("en-US"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                "family_name" to JsonObject(
                                    mapOf(
                                        "display" to JsonArray(
                                            listOf(
                                                JsonObject(
                                                    mapOf(
                                                        "name" to JsonPrimitive("Surname"),
                                                        "locale" to JsonPrimitive("en-US"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                                "degree" to JsonObject(emptyMap()),
                                "gpa" to JsonObject(
                                    mapOf(
                                        "display" to JsonArray(
                                            listOf(
                                                JsonObject(
                                                    mapOf(
                                                        "name" to JsonPrimitive("GPA"),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                emptyList(),
            )

        /**
         * Gets the [CredentialIssuerMetadata] used throughout these tests.
         */
        private fun credentialIssuerMetadata() =
            CredentialIssuerMetadata(
                CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                credentialEndpoint = CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials").getOrThrow(),
                credentialsSupported = listOf(universityDegreeJwt()),
            )
    }
}
