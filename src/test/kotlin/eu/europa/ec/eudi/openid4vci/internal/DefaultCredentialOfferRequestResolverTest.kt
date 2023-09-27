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
import eu.europa.ec.eudi.openid4vci.Credential.ScopedCredential
import eu.europa.ec.eudi.openid4vci.Credential.UnscopedCredential.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.Credential.UnscopedCredential.W3CVerifiableCredential
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
        val credentialOffer = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

        val expected = CredentialOffer(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            listOf(
                ScopedCredential("UniversityDegree_JWT"),
                MsoMdocCredential(MsoMdocObject(format = "mso_mdoc", docType = "org.iso.18013.5.1.mDL")),
            ),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        DefaultCredentialOfferRequestResolver().resolve(credentialEndpointUrl.toString())
            .fold(
                { Assertions.assertEquals(expected, it) },
                { Assertions.fail("Credential Offer resolution should have succeeded", it) },
            )
    }

    @Test
    fun `resolve success with mos_mdoc`() = runBlocking {
        val credentialOffer = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

        val expected = CredentialOffer(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            listOf(
                ScopedCredential("UniversityDegree_JWT"),
                MsoMdocCredential(
                    MsoMdocObject(
                        format = "mso_mdoc",
                        docType = "org.iso.18013.5.1.mDL",
                        cryptographicBindingMethodsSupported = listOf("mso"),
                        cryptographicSuitesSupported = listOf(
                            "ES256",
                            "ES384",
                            "ES512",
                        ),
                        display = listOf(
                            DisplayObject(
                                "Mobile Driving License",
                                "en-US",
                                DisplayObject.Logo(
                                    "https://examplestate.com/public/mdl.png",
                                    "a square figure of a mobile driving license",
                                ),
                                null,
                                "#12107c",
                                "#FFFFFF",
                            ),
                        ),
                        claims = mapOf(
                            "org.iso.18013.5.1" to mapOf(
                                "given_name" to MsoMdocObject.ClaimObject(
                                    display = listOf(
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            "Given Name",
                                            "en-US",
                                        ),
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            "名前",
                                            "ja-JP",
                                        ),
                                    ),
                                ),
                                "family_name" to MsoMdocObject.ClaimObject(
                                    display = listOf(
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            "Surname",
                                            "en-US",
                                        ),
                                    ),
                                ),
                                "birth_date" to MsoMdocObject.ClaimObject(),
                            ),
                            "org.iso.18013.5.1.aamva" to mapOf(
                                "organ_donor" to MsoMdocObject.ClaimObject(),
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

        DefaultCredentialOfferRequestResolver().resolve(credentialEndpointUrl.toString())
            .fold(
                { Assertions.assertEquals(expected, it) },
                { Assertions.fail("Credential Offer resolution should have succeeded", it) },
            )
    }

    @Test
    internal fun `resolve success with jwt_vc_json`() = runBlocking {
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

        val expected = CredentialOffer(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            listOf(
                W3CVerifiableCredential.SignedJwt(
                    W3CVerifiableCredentialSignedJwtObject(
                        "jwt_vc_json",
                        "UniversityDegree_JWT",
                        listOf("did:example"),
                        listOf("ES256K"),
                        listOf("jwt"),
                        listOf(
                            DisplayObject(
                                "University Credential",
                                "en-US",
                                DisplayObject.Logo(
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

        DefaultCredentialOfferRequestResolver().resolve(credentialEndpointUrl.toString())
            .fold(
                { Assertions.assertEquals(expected, it) },
                { Assertions.fail("Credential Offer resolution should have succeeded", it) },
            )
    }

    @Test
    internal fun `resolve success with ldp_vc`() = runBlocking {
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

        val expected = CredentialOffer(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            listOf(
                W3CVerifiableCredential.JsonLdDataIntegrity(
                    W3CVerifiableCredentialsJsonLdDataIntegrityObject(
                        "ldp_vc",
                        listOf(
                            "VerifiableCredential",
                            "UniversityDegreeCredential",
                        ),
                        listOf("did:example"),
                        listOf("Ed25519Signature2018"),
                        emptyList(),
                        listOf(
                            DisplayObject(
                                "University Credential",
                                "en-US",
                                DisplayObject.Logo(
                                    "https://exampleuniversity.com/public/logo.png",
                                    "a square logo of a university",
                                ),
                                null,
                                "#12107c",
                                "#FFFFFF",
                            ),
                        ),
                        null,
                        listOf(
                            "https://www.w3.org/2018/credentials/v1",
                            "https://www.w3.org/2018/credentials/examples/v1",
                        ),
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

        DefaultCredentialOfferRequestResolver().resolve(credentialEndpointUrl.toString())
            .fold(
                { Assertions.assertEquals(expected, it) },
                { Assertions.fail("Credential Offer resolution should have succeeded", it) },
            )
    }

    companion object {
        private fun getResourceAsText(resource: String): String =
            File(ClassLoader.getSystemResource(resource).path).readText()
    }
}
