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
import kotlinx.coroutines.runBlocking
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
                            MsoMdocObject.DisplayObject(
                                name = "Mobile Driving License",
                                locale = "en-US",
                                logo = MsoMdocObject.DisplayObject.Logo(
                                    url = "https://examplestate.com/public/mdl.png",
                                    alternativeText = "a square figure of a mobile driving license",
                                ),
                                backgroundColor = "#12107c",
                                textColor = "#FFFFFF",
                            ),
                        ),
                        claims = mapOf(
                            "org.iso.18013.5.1" to mapOf(
                                "given_name" to MsoMdocObject.ClaimObject(
                                    display = listOf(
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            name = "Given Name",
                                            locale = "en-US",
                                        ),
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            name = "名前",
                                            locale = "ja-JP",
                                        ),
                                    ),
                                ),
                                "family_name" to MsoMdocObject.ClaimObject(
                                    display = listOf(
                                        MsoMdocObject.ClaimObject.DisplayObject(
                                            name = "Surname",
                                            locale = "en-US",
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

    companion object {
        private fun getResourceAsText(resource: String): String =
            File(ClassLoader.getSystemResource(resource).path).readText()
    }
}
