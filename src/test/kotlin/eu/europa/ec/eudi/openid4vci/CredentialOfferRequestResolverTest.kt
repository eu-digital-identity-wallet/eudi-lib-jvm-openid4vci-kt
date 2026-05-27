/*
 * Copyright (c) 2023-2026 European Commission
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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.internal.CredentialOfferRequestResolver
import kotlinx.coroutines.test.runTest
import org.apache.http.client.utils.URIBuilder
import kotlin.test.*

internal class CredentialOfferRequestResolverTest {

    @Test
    internal fun `resolve success`() = runTest {
        val responseEncryptionJwk = ECKeyGenerator(Curve.P_256)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            { issuerSupported, _ ->
                EncryptionSpec(
                    recipientKey = responseEncryptionJwk,
                    encryptionMethod = issuerSupported.encryptionMethods.first(),
                    compressionAlgorithm = assertIs<PayloadCompression.Supported>(issuerSupported.payloadCompression).algorithms.first(),
                )
            },
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oauthMetaDataHandler,
        )

        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json")

        val credentialIssuerMetadata = credentialIssuerMetadata()
        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)
        val expected = CredentialOffer(
            SampleIssuer.Id,
            credentialIssuerMetadata,
            oauthAuthorizationServerMetadata(),
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
            ExchangeEncryptionSpecification(
                requestEncryptionSpec = EncryptionSpec(
                    recipientKey = credentialRequestEncryption.encryptionParameters.encryptionKeys.keys.first(),
                    encryptionMethod = EncryptionMethod.XC20P,
                    compressionAlgorithm = CompressionAlgorithm.DEF,
                ),
                responseEncryptionSpec = EncryptionSpec(
                    recipientKey = responseEncryptionJwk,
                    encryptionMethod = EncryptionMethod.XC20P,
                    compressionAlgorithm = CompressionAlgorithm.DEF,
                ),
            ),
            null,
        )

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()
        val config = OpenId4VCIConfiguration.copy(issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned)

        val offer = resolver.resolve(config, credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolve failure with unknown credential format`() = runTest {
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            ResponseEncryptionSpecFactory.DEFAULT,
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oauthMetaDataHandler,
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_unknown_format.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(uri = credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError.InvalidCredentials>(exception.error)
    }

    @Test
    internal fun `resolve failure with blank issuer_state in grant`() = runTest {
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            ResponseEncryptionSpecFactory.DEFAULT,
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oauthMetaDataHandler,
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_issuer_state.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(uri = credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError>(exception.error)
    }

    @Test
    internal fun `resolve failure with blank pre-authorized_code in grant`() = runTest {
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            ResponseEncryptionSpecFactory.DEFAULT,
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),

            oauthMetaDataHandler,
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_with_blank_pre_authorized_code.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(uri = credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError.InvalidGrants>(exception.error)
    }

    @Test
    internal fun `resolve failure with over-sized tx_code description in pre-authorized_code grant`() = runTest {
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            ResponseEncryptionSpecFactory.DEFAULT,
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),

            oauthMetaDataHandler,
        )
        val credentialOffer =
            getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_offer_over_sized_tx_code_description.json")

        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer", credentialOffer)
            .build()

        val exception = assertFailsWith<CredentialOfferRequestException> {
            resolver.resolve(uri = credentialEndpointUrl.toString()).getOrThrow()
        }
        assertIs<CredentialOfferRequestValidationError.InvalidGrants>(exception.error)
    }

    @Test
    internal fun `resolve success with credential_offer_uri`() = runTest {
        val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()

        val responseEncryptionJwk = ECKeyGenerator(Curve.P_256)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
            .generate()
        val resolver = resolver(
            RequestEncryptionSpecFactory.DEFAULT,
            { issuerSupported, _ ->
                EncryptionSpec(
                    recipientKey = responseEncryptionJwk,
                    encryptionMethod = issuerSupported.encryptionMethods.first(),
                    compressionAlgorithm = assertIs<PayloadCompression.Supported>(issuerSupported.payloadCompression).algorithms.first(),
                )
            },
            RequestMocker(
                match(SampleIssuer.WellKnownUrl.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
            ),
            oauthMetaDataHandler,
            RequestMocker(
                match(credentialOfferUri.value.toURI()),
                jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer.json"),
            ),
        )
        val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
            .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
            .build()

        val credentialIssuerMetadata = credentialIssuerMetadata()
        val credentialRequestEncryption =
            assertIs<CredentialRequestEncryption.Required>(credentialIssuerMetadata.credentialRequestEncryption)
        val expected = CredentialOffer(
            SampleIssuer.Id,
            credentialIssuerMetadata,
            oauthAuthorizationServerMetadata(),
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
            ExchangeEncryptionSpecification(
                requestEncryptionSpec = EncryptionSpec(
                    recipientKey = credentialRequestEncryption.encryptionParameters.encryptionKeys.keys.first(),
                    encryptionMethod = EncryptionMethod.XC20P,
                    compressionAlgorithm = CompressionAlgorithm.DEF,
                ),
                responseEncryptionSpec = EncryptionSpec(
                    recipientKey = responseEncryptionJwk,
                    encryptionMethod = EncryptionMethod.XC20P,
                    compressionAlgorithm = CompressionAlgorithm.DEF,
                ),
            ),
            null,
        )

        val offer = resolver.resolve(uri = credentialEndpointUrl.toString()).getOrThrow()
        assertEquals(expected, offer)
    }

    @Test
    internal fun `resolution fails when auth code flow is required but not supported by auth server`() =
        runTest {
            val credentialOfferUri = HttpsUrl("https://credential_offer/1").getOrThrow()
            val resolver = resolver(
                RequestEncryptionSpecFactory.DEFAULT,
                ResponseEncryptionSpecFactory.DEFAULT,
                RequestMocker(
                    match(SampleIssuer.WellKnownUrl.value.toURI()),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json"),
                ),
                oauthMetaDataHandler(
                    SampleAuthServer.Url,
                    "eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata_no_auth_endpoint.json",
                ),
                RequestMocker(
                    match(credentialOfferUri.value.toURI()),
                    jsonResponse("eu/europa/ec/eudi/openid4vci/internal/sample_credential_offer_auth_code.json"),
                ),
            )
            val credentialEndpointUrl = URIBuilder("wallet://credential_offer")
                .addParameter("credential_offer_uri", credentialOfferUri.value.toString())
                .build()
            val result = resolver.resolve(uri = credentialEndpointUrl.toString())
            val exception = assertIs<CredentialOfferRequestException>(result.exceptionOrNull())
            val error = assertIs<CredentialOfferRequestValidationError.InvalidGrants>(exception.error)
            val cause = assertIs<IllegalArgumentException>(error.reason)
            assertEquals(
                "Credential Offer requires Authorization Code Grant, but the Authorization Server does not support it",
                cause.message,
            )
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
    assertEquals(expected.exchangeEncryptionSpecification, offer.exchangeEncryptionSpecification)
    assertEquals(expected.dPoPCtx, offer.dPoPCtx)
}

private var oauthMetaDataHandler =
    oauthMetaDataHandler(
        SampleAuthServer.Url,
        "eu/europa/ec/eudi/openid4vci/internal/oauth_authorization_server_metadata.json",
    )

private fun resolver(
    requestEncryptionSpecFactory: RequestEncryptionSpecFactory,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
    vararg request: RequestMocker,
): CredentialOfferRequestResolver =
    CredentialOfferRequestResolver(
        mockedHttpClient(requestMockers = request),
        requestEncryptionSpecFactory,
        responseEncryptionSpecFactory,
    )

private val defaultCfg = OpenId4VCIConfiguration.copy(issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned)

private suspend fun CredentialOfferRequestResolver.resolve(
    config: OpenId4VCIConfig = defaultCfg,
    uri: String,
): Result<CredentialOffer> = runCatching {
    val request = CredentialOfferRequest(uri).getOrThrow()

    resolve(config, request).getOrThrow()
}
