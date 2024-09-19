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
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Test cases for [DefaultCredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolverTest {

    @Test
    fun `resolve a credential offer passed by value that contains a pre-authorized code grant without transaction code`() = runTest {
        mockedKtorHttpClientFactory(oidcWellKnownMocker(), authServerWellKnownMocker())
            .invoke()
            .use { httpClient ->
                val resolver = DefaultCredentialOfferRequestResolver(httpClient)
                val credentialOfferJson =
                    """
                    {
                        "credential_configuration_ids": ["eu.europa.ec.eudiw.pid_vc_sd_jwt"],
                        "credential_issuer": "https://credential-issuer.example.com",
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": "code"
                            }
                        }
                    }
                    """.trimIndent()
                val credentialOfferUri = URLBuilder()
                    .apply {
                        path("/credential_offer")
                        parameters.append("credential_offer", credentialOfferJson)
                    }
                    .buildString()
                val credentialOfferRequest = CredentialOfferRequest(credentialOfferUri).getOrThrow()

                val credentialOffer = resolver.resolve(credentialOfferRequest).getOrThrow()

                assertEquals("https://credential-issuer.example.com", credentialOffer.credentialIssuerIdentifier.value.toString())
                assertEquals(1, credentialOffer.credentialConfigurationIdentifiers.size)
                assertEquals("eu.europa.ec.eudiw.pid_vc_sd_jwt", credentialOffer.credentialConfigurationIdentifiers.first().value)
                val grants = assertNotNull(credentialOffer.grants)
                assertNull(grants.authorizationCode())
                val preAuthorizedCode = assertNotNull(grants.preAuthorizedCode())
                assertEquals("code", preAuthorizedCode.preAuthorizedCode)
                assertNull(preAuthorizedCode.txCode)
            }
    }

    @Test
    fun `resolve a credential offer passed by value that contains a pre-authorized code grant with transaction code`() = runTest {
        mockedKtorHttpClientFactory(oidcWellKnownMocker(), authServerWellKnownMocker())
            .invoke()
            .use { httpClient ->
                val resolver = DefaultCredentialOfferRequestResolver(httpClient)
                val credentialOfferJson =
                    """
                    {
                        "credential_configuration_ids": ["eu.europa.ec.eudiw.pid_vc_sd_jwt"],
                        "credential_issuer": "https://credential-issuer.example.com",
                        "grants": {
                            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                                "pre-authorized_code": "code",
                                "tx_code": {
                                    "description": "Please provide the one-time code.",
                                    "input_mode": "numeric",
                                    "length": 5
                                }
                            }
                        }
                    }
                    """.trimIndent()
                val credentialOfferUri = URLBuilder()
                    .apply {
                        path("/credential_offer")
                        parameters.append("credential_offer", credentialOfferJson)
                    }
                    .buildString()
                val credentialOfferRequest = CredentialOfferRequest(credentialOfferUri).getOrThrow()

                val credentialOffer = resolver.resolve(credentialOfferRequest).getOrThrow()

                assertEquals("https://credential-issuer.example.com", credentialOffer.credentialIssuerIdentifier.value.toString())
                assertEquals(1, credentialOffer.credentialConfigurationIdentifiers.size)
                assertEquals("eu.europa.ec.eudiw.pid_vc_sd_jwt", credentialOffer.credentialConfigurationIdentifiers.first().value)
                val grants = assertNotNull(credentialOffer.grants)
                assertNull(grants.authorizationCode())
                val preAuthorizedCode = assertNotNull(grants.preAuthorizedCode())
                assertEquals("code", preAuthorizedCode.preAuthorizedCode)
                val txCode = assertNotNull(preAuthorizedCode.txCode)
                assertEquals("Please provide the one-time code.", txCode.description)
                assertEquals(TxCodeInputMode.NUMERIC, txCode.inputMode)
                assertEquals(5, txCode.length)
            }
    }
}
