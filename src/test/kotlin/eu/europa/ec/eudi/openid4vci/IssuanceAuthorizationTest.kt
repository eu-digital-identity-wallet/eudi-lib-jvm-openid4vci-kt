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
import eu.europa.ec.eudi.openid4vci.internal.http.PushedAuthorizationRequestResponseTO
import eu.europa.ec.eudi.openid4vci.internal.http.TokenResponseTO
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import parPostApplyAssertionsAndGetFormData
import tokenPostApplyAuthFlowAssertionsAndGetFormData
import tokenPostApplyPreAuthFlowAssertionsAndGetFormData
import java.net.URI
import java.util.*
import kotlin.test.*

class IssuanceAuthorizationTest {
    @Test
    fun `successful authorization with authorization code flow (wallet initiated)`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(false) }

                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                        }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                        }
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }
                    },
                )

            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared = prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state // dummy don't use it
                authRequestPrepared
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                    .getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `successful authorization with authorization code flow`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(false) }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                        }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                        }
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }
                    },
                )

            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared = prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state
                authRequestPrepared
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                    .also { println(it) }
            }
        }

    @Test
    fun `successful authorization with pre-authorization code flow`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                    parPostMocker {
                        fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyPreAuthFlowAssertionsAndGetFormData() }
                    },
                )
            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                authorizeWithPreAuthorizationCode("1234").getOrThrow()
            }
        }

    @Test
    fun `(pre-auth flow) when pre-authorized grant's tx_code is of wrong length exception is raised`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                )

            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()

            with(issuer) {
                authorizeWithPreAuthorizationCode("123456")
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalArgumentException to be thrown but was not") {
                                it is IllegalArgumentException
                            }
                        },
                    )
            }
        }

    @Test
    fun `(pre-auth flow) when pre-authorized grant's tx_code is of wrong input mode exception is raised`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                )

            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()

            with(issuer) {
                authorizeWithPreAuthorizationCode("AbdSS2356")
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalArgumentException to be thrown but was not") {
                                it is IllegalArgumentException
                            }
                        },
                    )
            }
        }

    @Test
    fun `when par endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                    RequestMocker(
                        requestMatcher = endsWith("/ext/par/request", HttpMethod.Post),
                        responseBuilder = {
                            respond(
                                content =
                                    Json.encodeToString(
                                        PushedAuthorizationRequestResponseTO.Failure(
                                            "invalid_request",
                                            "The redirect_uri is not valid for the given client",
                                        ),
                                    ),
                                status = HttpStatusCode.BadRequest,
                                headers =
                                    headersOf(
                                        HttpHeaders.ContentType to listOf("application/json"),
                                    ),
                            )
                        },
                    ),
                )
            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                prepareAuthorizationRequest()
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected PushedAuthorizationRequestFailed to be thrown but was not") {
                                it is CredentialIssuanceError.PushedAuthorizationRequestFailed
                            }
                        },
                    )
            }
        }

    @Test
    fun `(auth code flow) when token endpoint responds with failure, exception AccessTokenRequestFailed is thrown`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                    parPostMocker(),
                    RequestMocker(
                        requestMatcher = endsWith("/token", HttpMethod.Post),
                        responseBuilder = {
                            respond(
                                content =
                                    Json.encodeToString(
                                        TokenResponseTO.Failure(
                                            error = "unauthorized_client",
                                        ),
                                    ),
                                status = HttpStatusCode.BadRequest,
                                headers =
                                    headersOf(
                                        HttpHeaders.ContentType to listOf("application/json"),
                                    ),
                            )
                        },
                    ),
                )
            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()

            with(issuer) {
                val parPlaced = prepareAuthorizationRequest().getOrThrow()
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = parPlaced.state
                parPlaced
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected AccessTokenRequestFailed to be thrown but was not") {
                                it is CredentialIssuanceError.AccessTokenRequestFailed
                            }
                        },
                    )
            }
        }

    @Test
    fun `(pre-auth code flow) when token endpoint responds with failure, exception AccessTokenRequestFailed is thrown`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                    RequestMocker(
                        requestMatcher = endsWith("/token", HttpMethod.Post),
                        responseBuilder = {
                            respond(
                                content =
                                    Json.encodeToString(
                                        TokenResponseTO.Failure(
                                            error = "unauthorized_client",
                                        ),
                                    ),
                                status = HttpStatusCode.BadRequest,
                                headers =
                                    headersOf(
                                        HttpHeaders.ContentType to listOf("application/json"),
                                    ),
                            )
                        },
                    ),
                )
            val offer = credentialOffer(OpenId4VCIConfiguration, mockedHttpClient, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()

            with(issuer) {
                authorizeWithPreAuthorizationCode("1234")
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected AccessTokenRequestFailed to be thrown but was not") {
                                it is CredentialIssuanceError.AccessTokenRequestFailed
                            }
                        },
                    )
            }
        }

    @Test
    fun `ensure not dpop proof is sent to par endpoint when authorization code binding is disabled`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val headers = request.headers
                        val dpopProof = headers[DPoP]
                        assertNull(dpopProof, "got dpop proof when authorization code binding was disabled")
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }
                    },
                )

            val config =
                OpenId4VCIConfigurationWithDpopSigner.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Required,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.None,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared = prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state
                authRequestPrepared
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                    .also { println(it) }
            }
        }

    @Test
    fun `ensure dpop proof is sent to par endpoint when authorization code binding is enabled`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val headers = request.headers
                        val dpopProof = headers[DPoP]
                        assertNotNull(dpopProof, "no dpop proof sent when authorization code binding was enabled")
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }
                    },
                )

            val config =
                OpenId4VCIConfigurationWithDpopSigner.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Required,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared = prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state
                authRequestPrepared
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
                    .also { println(it) }
            }
        }

    @Test
    fun `ensure dpop_jkt is sent to par endpoint and no dpop header when binding method is DPoPJkt`() =
        runTest {
            val dPoPSigningKey = CryptoGenerator.randomECSigningKey(Curve.P_256)
            val expectedDpopJkt = dPoPSigningKey.toPublicJWK().computeThumbprint().toString()
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(false) }
                        assertEquals(expectedDpopJkt, form.formData["dpop_jkt"], "dpop_jkt was not sent as expected")
                        assertNull(request.headers[DPoP], "no dpop proof header expected when binding method is DPoPJkt")
                    },
                    tokenPostMocker { request ->
                        with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }
                    },
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    dPoPUsage = DPoPUsage.IfSupported(DPoPConfig(ProvisionDPoPSigner(dPoPSigningKey))),
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Required,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state
                authRequestPrepared
                    .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState)
            }
        }

    @Test
    fun `ensure exception is thrown when dpop_jkt binding method is selected but DPoP is not configured`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Required,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                prepareAuthorizationRequest()
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalStateException to be thrown but was not") {
                                it is IllegalStateException
                            }
                        },
                    )
            }
        }

    @Test
    fun `ensure exception is thrown when dpop_jkt binding method is selected but thumbprint is not available`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfigurationWithDpopSigner.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Required,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                prepareAuthorizationRequest()
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalStateException to be thrown but was not") {
                                it is IllegalStateException
                            }
                        },
                    )
            }
        }

    @Test
    fun `ensure dpop_jkt is included in the authorization request url when PAR is not used and code DPoP binding is enabled`() =
        runTest {
            val dPoPSigningKey = CryptoGenerator.randomECSigningKey(Curve.P_256)
            val expectedDpopJkt = dPoPSigningKey.toPublicJWK().computeThumbprint().toString()
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    dPoPUsage = DPoPUsage.IfSupported(DPoPConfig(ProvisionDPoPSigner(dPoPSigningKey))),
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Never,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authorizationCodeURL = prepareAuthorizationRequest().getOrThrow().authorizationCodeURL.toString()
                assertTrue("dpop_jkt was not included in the authorization request url") {
                    authorizationCodeURL.contains("dpop_jkt=$expectedDpopJkt")
                }
            }
        }

    @Test
    fun `ensure dpop_jkt is included in the authorization request url when PAR is not used and binding method is DPoPHeader`() =
        runTest {
            val dPoPSigningKey = CryptoGenerator.randomECSigningKey(Curve.P_256)
            val expectedDpopJkt = dPoPSigningKey.toPublicJWK().computeThumbprint().toString()
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    dPoPUsage = DPoPUsage.IfSupported(DPoPConfig(ProvisionDPoPSigner(dPoPSigningKey))),
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Never,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPHeader,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authorizationCodeURL = prepareAuthorizationRequest().getOrThrow().authorizationCodeURL.toString()
                assertTrue("dpop_jkt was not included in the authorization request url") {
                    authorizationCodeURL.contains("dpop_jkt=$expectedDpopJkt")
                }
            }
        }

    @Test
    fun `ensure dpop_jkt is not included in the authorization request url when PAR is not used and code DPoP binding is disabled`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Never,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.None,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authorizationCodeURL = prepareAuthorizationRequest().getOrThrow().authorizationCodeURL.toString()
                assertFalse("dpop_jkt should not be included in the authorization request url") {
                    authorizationCodeURL.contains("dpop_jkt")
                }
            }
        }

    @Test
    fun `ensure exception is thrown when PAR is not used, code DPoP binding via dpop_jkt but DPoP is not configured`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfiguration.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Never,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                prepareAuthorizationRequest()
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalStateException to be thrown but was not") {
                                it is IllegalStateException
                            }
                        },
                    )
            }
        }

    @Test
    fun `ensure exception is thrown when PAR is not used, code DPoP binding via dpop_jkt but thumbprint is not available`() =
        runTest {
            val mockedHttpClient =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                )

            val config =
                OpenId4VCIConfigurationWithDpopSigner.copy(
                    grants =
                        SupportedGrants.AuthorizationCode(
                            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
                            parUsage = ParUsage.Never,
                            authResponseIssChecking = AuthorizationResponseIssChecking.Never,
                            authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.DPoPJkt,
                        ),
                )
            val offer = credentialOffer(config, mockedHttpClient, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = config,
                        credentialOffer = offer,
                        httpClient = mockedHttpClient,
                    ).getIssuerOrThrow()
            with(issuer) {
                prepareAuthorizationRequest()
                    .fold(
                        onSuccess = {
                            fail("Exception expected to be thrown")
                        },
                        onFailure = {
                            assertTrue("Expected an IllegalStateException to be thrown but was not") {
                                it is IllegalStateException
                            }
                        },
                    )
            }
        }

    private suspend fun credentialOffer(
        config: OpenId4VCIConfig,
        httpClient: HttpClient,
        credentialOfferStr: String,
    ): CredentialOffer =
        CredentialOffer
            .resolve(
                httpClient = httpClient,
                config = config,
                uri = "https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr",
            ).getOrThrow()
}
