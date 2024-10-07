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

internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oidcMetadataHandler,
        )

        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

        val expected = CredentialOffer(
            SampleIssuer.Id,
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(
                CredentialConfigurationIdentifier("UniversityDegree_JWT"),
                CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc"),
                CredentialConfigurationIdentifier("UniversityDegree_LDP_VC"),
                CredentialConfigurationIdentifier("UniversityDegree_JWT_VC_JSON-LD"),
            ),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", TxCode()),
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
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oidcMetadataHandler,
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
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oidcMetadataHandler,
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
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),

            oidcMetadataHandler,
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
    internal fun `resolve failure with over-sized tx_code description in pre-authorized_code grant`() = runTest {
        val resolver = resolver(
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),

            oidcMetadataHandler,
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_over_sized_tx_code_description.json")

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
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oidcMetadataHandler,
            RequestMocker(
                match(credentialOfferUri.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json"),
            ),
        )
        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
            .build()

        val expected = CredentialOffer(
            SampleIssuer.Id,
            credentialIssuerMetadata(),
            oidcAuthorizationServerMetadata(),
            listOf(
                CredentialConfigurationIdentifier("UniversityDegree_JWT"),
                CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc"),
                CredentialConfigurationIdentifier("UniversityDegree_LDP_VC"),
                CredentialConfigurationIdentifier("UniversityDegree_JWT_VC_JSON-LD"),
            ),
            Grants.Both(
                Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy"),
                Grants.PreAuthorizedCode("adhjhdjajkdkhjhdj", TxCode()),
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
    assertEquals(expected.credentialConfigurationIdentifiers, offer.credentialConfigurationIdentifiers)
    assertEquals(expected.grants, offer.grants)
}

private var oidcMetadataHandler =
    oidcMetaDataHandler(
        SampleAuthServer.Url,
        "eu/europa/ec/eudi/openid4vci/internal/oidc_authorization_server_metadata.json",
    )

private fun resolver(vararg request: RequestMocker): CredentialOfferRequestResolver =
    CredentialOfferRequestResolver(
        ktorHttpClientFactory = mockedKtorHttpClientFactory(requestMockers = request),
    )
