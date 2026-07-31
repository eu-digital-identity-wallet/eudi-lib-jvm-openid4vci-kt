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

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.RegistrationCertificatePolicy.Authorization
import eu.europa.ec.eudi.openid4vci.RegistrationCertificatePolicy.PolicyViolation
import kotlinx.coroutines.test.runTest
import java.net.URI
import kotlin.test.*

class IssuerTest {

    @Test
    fun `when wrprc policy provided then IssuerMetadataPolicy must be RequireSigned`() = runTest {
        assertFailsWith<IllegalArgumentException> {
            OpenId4VCIConfig(
                clientAuthentication = ClientAuthentication.None("MyWallet_ClientId"),
                authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                encryptionSupportConfig = EncryptionSupportConfig(Curve.P_256, 2048, CredentialResponseEncryptionPolicy.SUPPORTED),

                issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned,
                registrationCertificatePolicy = RegistrationCertificatePolicy { _, _, _ -> Authorization.Granted() },
            )
        }
    }

    @Test
    fun `when wrprc policy return violation warnings they are reflected on the IssuerResolutionResult`() = runTest {
        val warnings = listOf(
            PolicyViolation("WRPRC policy violation 1"),
            PolicyViolation("WRPRC policy violation 2"),
        )
        val config = OpenId4VCIConfiguration.copy(
            issuerMetadataPolicy = IssuerMetadataPolicy.RequireSigned(IssuerTrust({ _ -> true })),
            registrationCertificatePolicy = RegistrationCertificatePolicy { _, _, _ -> Authorization.Granted(warnings) },
        )
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerSignedMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
            credentialIssuerSignedMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
        )

        val issuerNegotiationResult = Issuer.makeWalletInitiated(
            config,
            SampleIssuer.Id,
            listOf(CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc")),
            mockedHttpClient,
        )

        issuerNegotiationResult.fold(
            onSuccess = {
                assertNotNull(it.second)
                assertEquals(warnings, it.second)
            },
            onFailure = { fail("Expected success") },
        )
    }

    @Test
    fun `when wrprc policy validation fails then issuer resolution fails with IssuerResolutionResult Failure`() = runTest {
        val policyViolation = PolicyViolation("You shall not pass!!")
        val config = OpenId4VCIConfiguration.copy(
            issuerMetadataPolicy = IssuerMetadataPolicy.RequireSigned(IssuerTrust({ _ -> true })),
            registrationCertificatePolicy = RegistrationCertificatePolicy { _, _, _ -> Authorization.NotGranted(policyViolation) },
        )
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerSignedMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
            credentialIssuerSignedMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
        )

        val issuerNegotiationResult = Issuer.makeWalletInitiated(
            config,
            SampleIssuer.Id,
            listOf(CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc")),
            mockedHttpClient,
        )

        issuerNegotiationResult.fold(
            onSuccess = { fail("Expected failure") },
            onFailure = { e ->
                assertIs<AuthorizationPolicyValidationError.AuthorizationPolicyNotMet>(e)
                assertEquals(policyViolation, e.violation)
            },
        )
    }

    @Test
    fun `verify wallet initiated`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(AuthServerMetadataVersion.FULL),
        )

        val issuer = Issuer.makeWalletInitiated(
            OpenId4VCIConfiguration,
            SampleIssuer.Id,
            listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            mockedHttpClient,
        ).getIssuerOrThrow()

        val credentialOffer = issuer.credentialOffer
        assertEquals(SampleIssuer.Id, credentialOffer.credentialIssuerIdentifier)
        assertEquals(1, credentialOffer.credentialConfigurationIdentifiers.size)
        assertEquals("eu.europa.ec.eudiw.pid_vc_sd_jwt", credentialOffer.credentialConfigurationIdentifiers.first().value)
        val grants = assertNotNull(credentialOffer.grants)
        val authorizationCodeGrant = assertNotNull(grants.authorizationCode())
        assertNull(authorizationCodeGrant.issuerState)
        assertEquals("https://auth-server.example.com", authorizationCodeGrant.authorizationServer?.value?.toExternalForm())
    }
}
