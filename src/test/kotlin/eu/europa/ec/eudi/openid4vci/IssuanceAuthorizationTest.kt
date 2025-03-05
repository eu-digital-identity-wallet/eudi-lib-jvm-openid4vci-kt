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

import eu.europa.ec.eudi.openid4vci.internal.http.PushedAuthorizationRequestResponseTO
import eu.europa.ec.eudi.openid4vci.internal.http.TokenResponseTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import parPostApplyAssertionsAndGetFormData
import tokenPostApplyAuthFlowAssertionsAndGetFormData
import tokenPostApplyPreAuthFlowAssertionsAndGetFormData
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceAuthorizationTest {

    @Test
    fun `successful authorization with authorization code flow (wallet initiated)`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oiciWellKnownMocker(),
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

        val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_NO_GRANTS)
        val issuer = Issuer.make(
            config = OpenId4VCIConfiguration,
            credentialOffer = offer,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        ).getOrThrow()
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow().also { println(it) }
            val authorizationCode = UUID.randomUUID().toString()
            val serverState = authRequestPrepared.state // dummy don't use it
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode), serverState).getOrThrow()
                .also { println(it) }
        }
    }

    @Test
    fun `successful authorization with authorization code flow`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                oiciWellKnownMocker(),
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

            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()
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
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
                parPostMocker {
                    fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
                },
                tokenPostMocker { request ->
                    with(request) { tokenPostApplyPreAuthFlowAssertionsAndGetFormData() }
                },
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()
            with(issuer) {
                authorizeWithPreAuthorizationCode("1234").getOrThrow()
            }
        }

    @Test
    fun `(pre-auth flow) when pre-authorized grant's tx_code is of wrong length exception is raised`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
            )

            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()

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
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
            )

            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()

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
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/ext/par/request", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                PushedAuthorizationRequestResponseTO.Failure(
                                    "invalid_request",
                                    "The redirect_uri is not valid for the given client",
                                ),
                            ),
                            status = HttpStatusCode.BadRequest,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    },
                ),
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()
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
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                TokenResponseTO.Failure(
                                    error = "unauthorized_client",
                                ),
                            ),
                            status = HttpStatusCode.BadRequest,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    },
                ),
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()

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
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oiciWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                TokenResponseTO.Failure(
                                    error = "unauthorized_client",
                                ),
                            ),
                            status = HttpStatusCode.BadRequest,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    },
                ),
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
            val issuer = Issuer.make(
                config = OpenId4VCIConfiguration,
                credentialOffer = offer,
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
            ).getOrThrow()

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

    private suspend fun credentialOffer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialOfferStr: String,
    ): CredentialOffer {
        return CredentialOfferRequestResolver(ktorHttpClientFactory, IssuerMetadataPolicy.RequireUnsigned)
            .resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()
    }
}
