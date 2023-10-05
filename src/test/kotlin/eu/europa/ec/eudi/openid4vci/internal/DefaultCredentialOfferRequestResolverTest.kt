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
import org.apache.http.client.utils.URIBuilder
import org.junit.jupiter.api.Assertions
import kotlin.test.Test

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() {
        runBlocking {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

                val universityDegreeJwt = universityDegreeJwt()
                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
                            universityDegreeJwt.credentialDefinition,
                            universityDegreeJwt.scope,
                        ),
                        OfferedCredential.MsoMdocCredential(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
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
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.MsoMdocCredential(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
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
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

                val universityDegreeJwt = universityDegreeJwt()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
                            universityDegreeJwt.credentialDefinition,
                            universityDegreeJwt.scope,
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
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata.json"),
                ),
                verifier = { Assertions.assertEquals(1, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

                val universityDegreeLdpVc = universityDegreeLdpVc()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.JsonLdDataIntegrity(
                            universityDegreeLdpVc.credentialDefinition,
                            universityDegreeLdpVc.scope,
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
                    match(credentialIssuerMetadataUrl().value),
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
                    match(credentialIssuerMetadataUrl().value),
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
                    match(credentialIssuerMetadataUrl().value),
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
                    match(credentialIssuerMetadataUrl().value),
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

                val universityDegreeJwt = universityDegreeJwt()
                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    listOf(
                        OfferedCredential.W3CVerifiableCredential.SignedJwt(
                            universityDegreeJwt.credentialDefinition,
                            universityDegreeJwt.scope,
                        ),
                        OfferedCredential.MsoMdocCredential(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
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
}
