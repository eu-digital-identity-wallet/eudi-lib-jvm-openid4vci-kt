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

import com.nimbusds.oauth2.sdk.rar.AuthorizationDetail
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointForm
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import parPost_ApplyAssertionsAndGetFormData
import tokenPost_ApplyAuthFlowAssertionsAndGetFormData
import tokenPost_ApplyPreAuthFlowAssertionsAndGetFormData
import java.net.URLDecoder
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class RichAuthorizationRequestTest {

    @Test
    fun `when AuthorizationDetailsInTokenRequest is Include in pre-authorization flow expect authorization_details`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            oidcWellKnownMocker(),
            parPostMocker {
                fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
            },
            tokenPostMocker { request ->
                val form = with(request) { tokenPost_ApplyPreAuthFlowAssertionsAndGetFormData() }

                val authorizationDetails = form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was expected but not sent.") {
                    authorizationDetails != null
                }

                // Validate that can be parsed as nimbus auth details
                val decoded = URLDecoder.decode(form.formData["authorization_details"], "UTF-8")
                val authDetails = AuthorizationDetail.parseList(decoded)
                assertTrue("Invalid authorization_details sent.") {
                    authDetails.all {
                        it.getField("credential_configuration_id") != null &&
                            it.getField("type") == "openid_credential"
                    }
                }
            },
        )
        val offer = credentialOffer(mockedKtorHttpClientFactory, CredentialOfferMixedDocTypes_PRE_AUTH_GRANT)
        val issuer = Issuer.make(
            config = OpenId4VCIConfiguration,
            credentialOffer = offer,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        ).getOrThrow()
        with(issuer) {
            authorizeWithPreAuthorizationCode(
                txCode = "1234",
                authDetailsOption = AuthorizationDetailsInTokenRequest.Include { true },
            ).getOrThrow()
        }
    }

    @Test
    fun `when config is FAVOR_SCOPES, auth details option is Include and all credentials have scopes no authorization_details expected`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                oidcWellKnownMocker(),
                authServerWellKnownMocker(),
                parPostMocker { request ->
                    val form = with(request) { parPost_ApplyAssertionsAndGetFormData(false) }
                    assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                        form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                    }
                    assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                        form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                    }
                },
                tokenPostMocker { request ->
                    val form = with(request) { tokenPost_ApplyAuthFlowAssertionsAndGetFormData() }

                    val authorizationDetails = form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                    assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was not expected but sent.") {
                        authorizationDetails == null
                    }
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
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AuthorizationDetailsInTokenRequest.Include { true },
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when config is FAVOR_SCOPES, auth details option is Include and some credentials have no scopes, expect authorization_details`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                // Oidc Well Known Mocker
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
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
                    with(request) { parPost_ApplyAssertionsAndGetFormData(false) }
                },
                tokenPostMocker { request ->
                    val form = with(request) { tokenPost_ApplyAuthFlowAssertionsAndGetFormData() }

                    val authorizationDetails = form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                    assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was expected but not sent.") {
                        authorizationDetails != null
                    }
                    // Validate that can be parsed as nimbus auth details
                    val decoded = URLDecoder.decode(form.formData["authorization_details"], "UTF-8")
                    val authDetails = AuthorizationDetail.parseList(decoded)
                    assertTrue("Invalid authorization_details sent.") {
                        authDetails.all {
                            it.getField("credential_configuration_id") != null &&
                                it.getField("type") == "openid_credential"
                        }
                    }
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
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AuthorizationDetailsInTokenRequest.Include { true },
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when FAVOR_SCOPES, auth details option is DoNotInclude and credentials have no scope attribute, no authorization_details`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                // Oidc Well Known Mocker
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
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
                    with(request) { parPost_ApplyAssertionsAndGetFormData(false) }
                },
                tokenPostMocker { request ->
                    val form = with(request) { tokenPost_ApplyAuthFlowAssertionsAndGetFormData() }

                    val authorizationDetails = form.formData[TokenEndpointForm.AUTHORIZATION_DETAILS]
                    assertTrue("Parameter ${TokenEndpointForm.AUTHORIZATION_DETAILS} was not expected but sent.") {
                        authorizationDetails == null
                    }
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
                    .authorizeWithAuthorizationCode(
                        authorizationCode = AuthorizationCode(authorizationCode),
                        serverState = serverState,
                        authDetailsOption = AuthorizationDetailsInTokenRequest.DoNotInclude,
                    ).getOrThrow()
                    .also { println(it) }
            }
        }

    @Test
    fun `when one of the offer credentials has no scope, then expect 'authorization_details' and 'scope' parameter in request`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker { request ->
                    val form = with(request) { parPost_ApplyAssertionsAndGetFormData(true) }
                    assertTrue("Missing authorization_details request attribute") {
                        form.formData["authorization_details"] != null
                    }
                    val authDetails = AuthorizationDetail.parseList(form.formData["authorization_details"])
                    assertTrue("Missing authorization_details eu.europa.ec.eudiw.pid_mso_mdoc") {
                        authDetails.any {
                            it.getField("credential_configuration_id") != null &&
                                it.getField("credential_configuration_id").equals("eu.europa.ec.eudiw.pid_mso_mdoc")
                        }
                    }

                    assertTrue("Missing scope attribute") {
                        form.formData["scope"] != null
                    }
                    assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                        form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                    }
                },
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_no_scopes.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
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

            val authRequestPrepared = issuer.prepareAuthorizationRequest().getOrThrow()
                .also { println(it) }

            // If authorization details were sent in the PAR post then identifiers sent must be stored in the state
            assert(authRequestPrepared.identifiersSentAsAuthDetails.isNotEmpty())
        }

    private suspend fun credentialOffer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialOfferStr: String,
    ): CredentialOffer {
        return CredentialOfferRequestResolver(ktorHttpClientFactory = ktorHttpClientFactory)
            .resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()
    }
}
