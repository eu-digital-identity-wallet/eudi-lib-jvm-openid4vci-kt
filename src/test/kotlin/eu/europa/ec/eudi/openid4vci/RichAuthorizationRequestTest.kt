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

import com.eygraber.uri.Uri
import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import com.nimbusds.openid.connect.sdk.Prompt
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointForm
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertThrows
import parPostApplyAssertionsAndGetFormData
import tokenPostApplyAuthFlowAssertionsAndGetFormData
import tokenPostApplyPreAuthFlowAssertionsAndGetFormData
import java.net.URI
import java.net.URLDecoder
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

class RichAuthorizationRequestTest {
    @Test
    fun `when AuthorizationDetailsInTokenRequest is Include in pre-authorization flow expect authorization_details`() =
        runTest {
            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    credentialIssuerMetadataWellKnownMocker(),
                    parPostMocker {
                        fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
                    },
                    tokenPostMocker { request ->
                        val form =
                            with(request) { tokenPostApplyPreAuthFlowAssertionsAndGetFormData() }

                        val authorizationDetails =
                            form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                        assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was expected but not sent.") {
                            authorizationDetails != null
                        }

                        // Validate that can be parsed as nimbus auth details
                        val decoded =
                            URLDecoder.decode(form.formData["authorization_details"], "UTF-8")
                        val authDetails = AuthorizationDetail.parseList(decoded)
                        assertTrue("Invalid authorization_details sent.") {
                            authDetails.all {
                                it.getField("credential_configuration_id") != null &&
                                    it.getField("type") == "openid_credential"
                            }
                        }
                    },
                )
            val offer =
                credentialOffer(
                    mockedKtorHttpClientFactory,
                    CredentialOfferMixedDocTypes_PRE_AUTH_GRANT,
                )
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()
            with(issuer) {
                authorizeWithPreAuthorizationCode(
                    txCode = "1234",
                    authDetailsOption = AccessTokenOption.Limited { true },
                ).getOrThrow()
            }
        }

    @Test
    fun `when config is FAVOR_SCOPES, auth details option is Include and all credentials have scopes no authorization_details expected`() =
        runTest {
            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    credentialIssuerMetadataWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(false) }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt")
                                ?: false
                        }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc")
                                ?: false
                        }
                    },
                    tokenPostMocker { request ->
                        val form =
                            with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }

                        val authorizationDetails =
                            form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                        assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was not expected but sent.") {
                            authorizationDetails == null
                        }
                    },
                )

            val offer =
                credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared =
                    prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state // dummy don't use it
                authRequestPrepared
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AccessTokenOption.Limited { true },
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when config is FAVOR_SCOPES, auth details option is Include and some credentials have no scopes, expect authorization_details`() =
        runTest {
            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    // Credential Issuer Metadata Well Known Mocker
                    RequestMocker(
                        requestMatcher =
                            endsWith(
                                "/.well-known/openid-credential-issuer",
                                HttpMethod.Get,
                            ),
                        responseBuilder = {
                            respond(
                                content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                            )
                        },
                    ),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        with(request) { parPostApplyAssertionsAndGetFormData(false) }
                    },
                    tokenPostMocker { request ->
                        val form =
                            with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }

                        val authorizationDetails =
                            form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                        assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was expected but not sent.") {
                            authorizationDetails != null
                        }
                        // Validate that can be parsed as nimbus auth details
                        val decoded =
                            URLDecoder.decode(form.formData["authorization_details"], "UTF-8")
                        val authDetails = AuthorizationDetail.parseList(decoded)
                        assertTrue("Invalid authorization_details sent.") {
                            authDetails.all {
                                it.getField("credential_configuration_id") != null &&
                                    it.getField("type") == "openid_credential"
                            }
                        }
                    },
                )

            val offer =
                credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()
            with(issuer) {
                val authRequestPrepared =
                    prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state // dummy don't use it
                authRequestPrepared
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AccessTokenOption.Limited { true },
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when FAVOR_SCOPES, auth details option is DoNotInclude and credentials have no scope attribute, no authorization_details`() =
        runTest {
            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    // Credential Issuer Metadata Well Known Mocker
                    RequestMocker(
                        requestMatcher =
                            endsWith(
                                "/.well-known/openid-credential-issuer",
                                HttpMethod.Get,
                            ),
                        responseBuilder = {
                            respond(
                                content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                            )
                        },
                    ),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        with(request) { parPostApplyAssertionsAndGetFormData(false) }
                    },
                    tokenPostMocker { request ->
                        val form =
                            with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() }

                        val authorizationDetails =
                            form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                        assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was not expected but sent.") {
                            authorizationDetails == null
                        }
                    },
                )

            val offer =
                credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_NO_GRANTS)
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()

            with(issuer) {
                val authRequestPrepared =
                    prepareAuthorizationRequest().getOrThrow().also { println(it) }
                val authorizationCode = UUID.randomUUID().toString()
                val serverState = authRequestPrepared.state // dummy don't use it
                authRequestPrepared
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AccessTokenOption.AsRequested,
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when one of the offer credentials has no scope, then expect 'authorization_details' and 'scope' parameter in request`() =
        runTest {
            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(true) }
                        assertTrue("Missing authorization_details request attribute") {
                            form.formData["authorization_details"] != null
                        }
                        val authDetails =
                            AuthorizationDetail.parseList(form.formData["authorization_details"])
                        assertTrue("Missing authorization_details eu.europa.ec.eudiw.pid_mso_mdoc") {
                            authDetails.any {
                                it.getField("credential_configuration_id") != null &&
                                    it
                                        .getField("credential_configuration_id")
                                        .equals("eu.europa.ec.eudiw.pid_mso_mdoc")
                            }
                        }

                        assertTrue("Missing scope attribute") {
                            form.formData["scope"] != null
                        }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt")
                                ?: false
                        }
                    },
                    RequestMocker(
                        requestMatcher =
                            endsWith(
                                "/.well-known/openid-credential-issuer",
                                HttpMethod.Get,
                            ),
                        responseBuilder = {
                            respond(
                                content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                            )
                        },
                    ),
                )
            val offer =
                credentialOffer(
                    mockedKtorHttpClientFactory,
                    CredentialOfferMixedDocTypes_AUTH_GRANT,
                )
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()

            val authRequestPrepared =
                issuer
                    .prepareAuthorizationRequest()
                    .getOrThrow()
                    .also { println(it) }

            // If authorization details were sent in the PAR post then identifiers sent must be stored in the state
            assert(authRequestPrepared.identifiersSentAsAuthDetails.isNotEmpty())
        }

    @Test
    fun `when additional parameters are provided, then expect custom parameters included in the PAR request`() =
        runTest {
            val additionalParameters =
                AdditionalParameters(
                    "customParamKey" to "customParamValue",
                    "prompt" to "login",
                )

            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        val form = with(request) { parPostApplyAssertionsAndGetFormData(true) }
                        assertEquals(
                            setOf(
                                "resource",
                                "response_type",
                                "issuer_state",
                                "code_challenge_method",
                                "client_id",
                                "authorization_details",
                                "scope",
                                "redirect_uri",
                                "state",
                                "customParamKey",
                                "code_challenge",
                                "prompt",
                            ),
                            form.formData.names(),
                        )
                        assertEquals("customParamValue", form.formData["customParamKey"])
                        assertEquals("login", form.formData["prompt"])
                    },
                    RequestMocker(
                        requestMatcher =
                            endsWith(
                                "/.well-known/openid-credential-issuer",
                                HttpMethod.Get,
                            ),
                        responseBuilder = {
                            respond(
                                content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                            )
                        },
                    ),
                )
            val offer =
                credentialOffer(
                    mockedKtorHttpClientFactory,
                    CredentialOfferMixedDocTypes_AUTH_GRANT,
                )
            val issuer =
                Issuer
                    .make(
                        config = OpenId4VCIConfiguration,
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()

            val request =
                issuer
                    .prepareAuthorizationRequest(additionalParameters = additionalParameters)
                    .getOrThrow()
                    .also { println(it) }

            val uri = Uri.parse(request.authorizationCodeURL.value.toExternalForm())
            assertEquals(
                setOf("client_id", "request_uri"),
                uri.getQueryParameterNames(),
            )
        }

    @Test
    fun `when additional parameters are provided, then expect custom parameters included in the Authorization Request request`() =
        runTest {
            val additionalParameters =
                AdditionalParameters(
                    "customParamKey" to "customParamValue",
                    "prompt" to "login",
                )

            val mockedKtorHttpClientFactory =
                mockedHttpClient(
                    authServerWellKnownMocker(),
                    RequestMocker(
                        requestMatcher =
                            endsWith(
                                "/.well-known/openid-credential-issuer",
                                HttpMethod.Get,
                            ),
                        responseBuilder = {
                            respond(
                                content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                            )
                        },
                    ),
                )
            val offer =
                credentialOffer(
                    mockedKtorHttpClientFactory,
                    CredentialOfferMixedDocTypes_AUTH_GRANT,
                )
            val issuer =
                Issuer
                    .make(
                        config =
                            OpenId4VCIConfiguration.copy(
                                grants =
                                    SupportedGrants.AuthorizationCode(
                                        authFlowRedirectionURI = URI.create("eudi-wallet://auth"),
                                        parUsage = ParUsage.Never,
                                        authorizationCodeDPoPBindingMethod = AuthorizationCodeDPoPBindingMethod.None,
                                    ),
                            ),
                        credentialOffer = offer,
                        httpClient = mockedKtorHttpClientFactory,
                    ).getIssuerOrThrow()

            val request =
                issuer
                    .prepareAuthorizationRequest(additionalParameters = additionalParameters)
                    .getOrThrow()
                    .also { println(it) }

            val uri = Uri.parse(request.authorizationCodeURL.value.toExternalForm())

            assertEquals(
                setOf(
                    "resource",
                    "response_type",
                    "issuer_state",
                    "code_challenge_method",
                    "client_id",
                    "authorization_details",
                    "scope",
                    "redirect_uri",
                    "state",
                    "prompt",
                    "customParamKey",
                    "code_challenge",
                ),
                uri.getQueryParameterNames(),
            )
            assertEquals("customParamValue", uri.getQueryParameter("customParamKey"))
            assertEquals("login", uri.getQueryParameter("prompt"))
        }

    @Test
    fun `when forbidden parameters are provided, then throw error`() {
        assertThrows<IllegalArgumentException> {
            AdditionalParameters(
                mapOf(
                    "response_type" to "value1",
                    "client_id" to "value2",
                ),
            )
        }
    }

    private suspend fun credentialOffer(
        httpClient: HttpClient,
        credentialOfferStr: String,
    ): CredentialOffer {
        val config =
            OpenId4VCIConfiguration.copy(issuerMetadataPolicy = IssuerMetadataPolicy.IgnoreSigned)
        return CredentialOffer
            .resolve(
                httpClient = httpClient,
                config = config,
                uri = "https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr",
            ).getOrThrow()
    }
}
