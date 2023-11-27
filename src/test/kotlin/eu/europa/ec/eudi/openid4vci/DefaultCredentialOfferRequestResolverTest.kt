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

import kotlinx.coroutines.test.runTest
import org.apache.http.client.utils.URIBuilder
import kotlin.test.*
import kotlin.time.Duration.Companion.seconds

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )

        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(
                CredentialIdentifier("UniversityDegree_JWT"),
                CredentialIdentifier("MobileDrivingLicense_msoMdoc"),
            ),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }

    @Test
    fun `resolve success with mos_mdoc`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )

        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/mso_mdoc_credential_offer.json")

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(CredentialIdentifier("MobileDrivingLicense_msoMdoc")),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolve success with jwt_vc_json`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json_credential_offer.json")

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(CredentialIdentifier("UniversityDegree_JWT")),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolve success with ldp_vc`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/ldp_vc_credential_offer.json")

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(CredentialIdentifier("UniversityDegree_LDP_VC")),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()

        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolve success with jwt_vc_json-ld`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )

        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/jwt_vc_json-ld_credential_offer.json")

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(CredentialIdentifier("UniversityDegree_JWT_VC_JSON-LD")),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()

        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolve failure with unknown credential format`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_unknown_format.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError.InvalidCredentials>(exception.error)
    }

    @Test
    internal fun `resolve failure with blank issuer_state in grant`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_issuer_state.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError>(exception.error)
    }

    @Test
    internal fun `resolve failure with blank pre-authorized_code in grant`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_pre_authorized_code.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError.InvalidGrants>(exception.error)
    }

    @Test
    internal fun `resolve success with credential_offer_uri`() = runTest {
        val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()

        val resolver = resolver(
            RequestMocker(
                match(credentialIssuerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            RequestMocker(
                match(oidcAuthorizationServerMetadataUrl().value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json"),
            ),
            RequestMocker(
                match(credentialOfferUri.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json"),
            ),
        )
        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
            .build()

        val expected = CredentialOffer(
            credentialIssuerId(),
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(CredentialIdentifier("MobileDrivingLicense_msoMdoc")),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", true, 5.seconds),
            ),
        )

        val offer = resolver.resolve(credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }
}

private fun assertEquals(expected: CredentialOffer, offer: CredentialOffer) {
    assertEquals(expected.credentialIssuerIdentifier, offer.credentialIssuerIdentifier)
    assertEquals(expected.credentialIssuerMetadata, offer.credentialIssuerMetadata)
    // equals not implemented by OIDCProviderMetadata
    assertEquals(
        expected.authorizationServerMetadata.toJSONObject(),
        offer.authorizationServerMetadata.toJSONObject(),
    )
    assertEquals(expected.credentials, offer.credentials)
    assertEquals(expected.grants, offer.grants)
}

private fun resolver(vararg request: RequestMocker): CredentialOfferRequestResolver =
    CredentialOfferRequestResolver(
        ktorHttpClientFactory = mockedKtorHttpClientFactory(requestMockers = request),
    )
