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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.apache.http.client.utils.URIBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    oidcAuthorizationServerMetadata(),
                    listOf(
                        CredentialMetadata.ByScope(Scope.of("UniversityDegree_JWT")),
                        MsoMdocFormat.CredentialMetadata(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                    ),
                )

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        {
                            assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                            assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                            // equals not implemented by OIDCProviderMetadata
                            assertEquals(
                                expected.authorizationServerMetadata.toJSONObject(),
                                it.authorizationServerMetadata.toJSONObject(),
                            )
                            assertEquals(expected.credentials, it.credentials)
                            assertEquals(expected.grants, it.grants)
                        },
                        { fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }

    @Test
    fun `resolve success with mos_mdoc`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    oidcAuthorizationServerMetadata(),
                    listOf(
                        MsoMdocFormat.CredentialMetadata(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                    ),
                )

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        {
                            assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                            assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                            // equals not implemented by OIDCProviderMetadata
                            assertEquals(
                                expected.authorizationServerMetadata.toJSONObject(),
                                it.authorizationServerMetadata.toJSONObject(),
                            )
                            assertEquals(expected.credentials, it.credentials)
                            assertEquals(expected.grants, it.grants)
                        },
                        { fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }

    @Test
    internal fun `resolve success with jwt_vc_json`() = runTest {
        mockEngine(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
            verifier = { assertEquals(2, it.size) },
        ) { httpGet ->
            val credentialOffer =
                getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

            val universityDegreeJwt = universityDegreeJwt()
            val expected = CredentialOffer(
                credentialIssuerId(),
                credentialIssuerMetadata(),
                oidcAuthorizationServerMetadata(),
                listOf(
                    W3CSignedJwtFormat.CredentialMetadata(
                        W3CSignedJwtFormat.CredentialMetadata.CredentialDefinitionMetadata(
                            universityDegreeJwt.credentialDefinition.type,
                        ),
                        universityDegreeJwt.scope,
                    ),
                ),
                Grants.Both(
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                    Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                ),
            )

            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer", credentialOffer)
                .build()

            DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                .resolve(credentialEndpointUrl.toString())
                .fold(
                    {
                        assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                        assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                        // equals not implemented by OIDCProviderMetadata
                        assertEquals(
                            expected.authorizationServerMetadata.toJSONObject(),
                            it.authorizationServerMetadata.toJSONObject(),
                        )
                        assertEquals(expected.credentials, it.credentials)
                        assertEquals(expected.grants, it.grants)
                    },
                    { fail("Credential Offer resolution should have succeeded", it) },
                )
        }
    }

    @Test
    internal fun `resolve success with ldp_vc`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

                val universityDegreeLdpVc = universityDegreeLdpVc()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    oidcAuthorizationServerMetadata(),
                    listOf(
                        W3CJsonLdDataIntegrityFormat.CredentialMetadata(
                            W3CJsonLdDataIntegrityFormat.CredentialMetadata.CredentialDefinitionMetadata(
                                universityDegreeLdpVc.credentialDefinition.context,
                                universityDegreeLdpVc.credentialDefinition.type,
                            ),
                            universityDegreeLdpVc.scope,
                        ),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                    ),
                )

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        {
                            assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                            assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                            // equals not implemented by OIDCProviderMetadata
                            assertEquals(
                                expected.authorizationServerMetadata.toJSONObject(),
                                it.authorizationServerMetadata.toJSONObject(),
                            )
                            assertEquals(expected.credentials, it.credentials)
                            assertEquals(expected.grants, it.grants)
                        },
                        { fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }

    @Test
    internal fun `resolve success with jwt_vc_json-ld`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json-ld_credential_offer.json")

                val universityDegreeJwtVcJsonLD = universityDegreeJwtVcJsonLD()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    oidcAuthorizationServerMetadata(),
                    listOf(
                        W3CJsonLdSignedJwtFormat.CredentialMetadata(
                            W3CJsonLdSignedJwtFormat.CredentialMetadata.CredentialDefinitionMetadata(
                                universityDegreeJwtVcJsonLD.credentialDefinition.context,
                                universityDegreeJwtVcJsonLD.credentialDefinition.type,
                            ),
                            universityDegreeJwtVcJsonLD.scope,
                        ),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                    ),
                )

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        {
                            assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                            assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                            // equals not implemented by OIDCProviderMetadata
                            assertEquals(
                                expected.authorizationServerMetadata.toJSONObject(),
                                it.authorizationServerMetadata.toJSONObject(),
                            )
                            assertEquals(expected.credentials, it.credentials)
                            assertEquals(expected.grants, it.grants)
                        },
                        { fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }

    @Test
    internal fun `resolve failure with unknown credential format`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_unknown_format.json")

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        { fail("Credential Offer resolution should have failed") },
                        {
                            val exception = assertIs<CredentialOfferRequestException>(it)
                            assertIs<CredentialOfferRequestValidationError.InvalidCredentials>(exception.error)
                        },
                    )
            }
        }
    }

    @Test
    internal fun `resolve failure with blank issuer_state in grant`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_issuer_state.json")

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        { fail("Credential Offer resolution should have failed") },
                        {
                            val exception = assertIs<CredentialOfferRequestException>(it)
                            assertIs<CredentialOfferRequestValidationError>(
                                exception.error,
                            )
                        },
                    )
            }
        }
    }

    @Test
    internal fun `resolve failure with blank pre-authorized_code in grant`() {
        runTest {
            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                verifier = { assertEquals(2, it.size) },
            ) { httpGet ->
                val credentialOffer =
                    getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_pre_authorized_code.json")

                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer", credentialOffer)
                    .build()

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        { fail("Credential Offer resolution should have failed") },
                        {
                            val exception = assertIs<CredentialOfferRequestException>(it)
                            assertIs<CredentialOfferRequestValidationError.InvalidGrants>(
                                exception.error,
                            )
                        },
                    )
            }
        }
    }

    @Test
    internal fun `resolve success with credential_offer_uri`() {
        runTest {
            val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()

            mockEngine(
                RequestMocker(
                    match(credentialIssuerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                RequestMocker(
                    match(oidcAuthorizationServerMetadataUrl().value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
                ),
                RequestMocker(
                    match(credentialOfferUri.value),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json"),
                ),
                verifier = { assertEquals(3, it.size) },
            ) { httpGet ->
                val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                    .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
                    .build()

                val mobileDrivingLicense = mobileDrivingLicense()
                val expected = CredentialOffer(
                    credentialIssuerId(),
                    credentialIssuerMetadata(),
                    oidcAuthorizationServerMetadata(),
                    listOf(
                        CredentialMetadata.ByScope(Scope.of("UniversityDegree_JWT")),
                        MsoMdocFormat.CredentialMetadata(mobileDrivingLicense.docType, mobileDrivingLicense.scope),
                    ),
                    Grants.Both(
                        Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                        Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
                    ),
                )

                DefaultCredentialOfferRequestResolver(Dispatchers.IO, httpGet)
                    .resolve(credentialEndpointUrl.toString())
                    .fold(
                        {
                            assertEquals(expected.credentialIssuerIdentifier, it.credentialIssuerIdentifier)
                            assertEquals(expected.credentialIssuerMetadata, it.credentialIssuerMetadata)
                            // equals not implemented by OIDCProviderMetadata
                            assertEquals(
                                expected.authorizationServerMetadata.toJSONObject(),
                                it.authorizationServerMetadata.toJSONObject(),
                            )
                            assertEquals(expected.credentials, it.credentials)
                            assertEquals(expected.grants, it.grants)
                        },
                        { fail("Credential Offer resolution should have succeeded", it) },
                    )
            }
        }
    }
}
