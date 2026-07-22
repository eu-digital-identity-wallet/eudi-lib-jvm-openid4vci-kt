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

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class IssuerTest {

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
