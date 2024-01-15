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

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.internal.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLEncoder
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceAuthorizationTest {

    val CredentialIssuer_URL = "https://credential-issuer.example.com"

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CredentialIssuer_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"],
          "grants": {
            "authorization_code": {
              "issuer_state": "eyJhbGciOiJSU0EtFYUaBy"
            }
          }
        }
    """.trimIndent()

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS = """
        {
          "credential_issuer": "$CredentialIssuer_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"]          
        }
    """.trimIndent()

    private val PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CredentialIssuer_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"],
          "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": "eyJhbGciOiJSU0EtFYUaBy",
              "user_pin_required": true
            }
          }
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    )

    @Test
    fun `successful authorization with authorization code flow (wallet initiated)`() = runTest {
        val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { request ->
                assertTrue(
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                ) {
                    request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                }
                assertTrue("Not a form post") {
                    request.body is FormDataContent
                }
                val form = request.body as FormDataContent

                assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                    form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                }
                assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                    form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                }
                assertTrue("No issuer_state expected when issuance starts from wallet") {
                    form.formData["issuer_state"] == null
                }
                assertTrue("PKCE code challenge was expected but not sent.") {
                    form.formData["code_challenge"] != null
                }
                assertTrue("PKCE code challenge method was expected but not sent.") {
                    form.formData["code_challenge_method"] != null
                }
            },
            tokenPostMocker { request ->
                assertTrue(
                    "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                ) {
                    request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                }
                assertTrue("Not a form post") {
                    request.body is FormDataContent
                }
                val form = request.body as FormDataContent
                assertTrue("PKCE code verifier was expected but not sent.") {
                    form.formData[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM] != null
                }
                assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.") {
                    form.formData[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM] != null
                }
                assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.") {
                    form.formData[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM] != null
                }
                assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.") {
                    form.formData[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM] != null
                }
                val grantType = form.formData[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.") {
                    grantType != null
                }
                assertTrue(
                    "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                ) {
                    grantType == TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE
                }
            },
        )

        val offer = credentialOffer(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS)
        val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
        val issuerState = issuerStateFromOffer(offer)

        with(issuer) {
            val parRequested =
                pushAuthorizationCodeRequest(offer.credentials, issuerState).getOrThrow()
                    .also { println(it) }

            val authorizationCode = UUID.randomUUID().toString()

            parRequested
                .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                .also { println(it) }
                .requestAccessToken().getOrThrow().also { println(it) }
        }
    }

    @Test
    fun `successful authorization with authorization code flow`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                oidcWellKnownMocker(),
                authServerWellKnownMocker(),
                parPostMocker { request ->
                    assertTrue(
                        "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                    ) {
                        request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                    }
                    assertTrue("Not a form post") {
                        request.body is FormDataContent
                    }

                    val form = request.body as FormDataContent

                    assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                        form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                    }
                    assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                        form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                    }
                    assertTrue("No issuer_state expected when issuance starts from wallet") {
                        form.formData["issuer_state"] == null
                    }
                    assertTrue("PKCE code challenge was expected but not sent.") {
                        form.formData["code_challenge"] != null
                    }
                    assertTrue("PKCE code challenge method was expected but not sent.") {
                        form.formData["code_challenge_method"] != null
                    }
                },
                tokenPostMocker { request ->
                    assertTrue(
                        "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                    ) {
                        request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                    }
                    assertTrue("Not a form post") {
                        request.body is FormDataContent
                    }
                    val form = request.body as FormDataContent
                    assertTrue("PKCE code verifier was expected but not sent.") {
                        form.formData[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM] != null
                    }
                    assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.") {
                        form.formData[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM] != null
                    }
                    assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.") {
                        form.formData[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM] != null
                    }
                    assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.") {
                        form.formData[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM] != null
                    }
                    val grantType = form.formData[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.") {
                        grantType != null
                    }
                    assertTrue(
                        "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                    ) {
                        grantType == TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE
                    }
                },
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            with(issuer) {
                val parRequested =
                    pushAuthorizationCodeRequest(
                        listOf(
                            CredentialIdentifier("eu.europa.ec.eudiw.pid_mso_mdoc"),
                            CredentialIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                        ),
                        null,
                    ).getOrThrow()

                val authorizationCode = UUID.randomUUID().toString()

                parRequested
                    .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                    .also { println(it) }
                    .requestAccessToken().getOrThrow().also { println(it) }
            }
        }

    @Test
    fun `successful authorization with pre-authorization code flow`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                parPostMocker {
                    fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
                },
                tokenPostMocker { request ->
                    assertTrue(
                        "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                    ) {
                        request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                    }
                    assertTrue("Not a form post") {
                        request.body is FormDataContent
                    }
                    val form = request.body as FormDataContent

                    assertTrue("PKCE code verifier was not expected but sent.") {
                        form.formData["code_verifier"] != null
                    }
                    assertTrue("Parameter ${TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM} was expected but not sent.") {
                        form.formData[TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM] != null
                    }
                    assertTrue("Parameter ${TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM} was expected but not sent.") {
                        form.formData[TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM] != null
                    }

                    val grantType = form.formData[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.") {
                        grantType != null
                    }

                    val grantTypeParamValueUrlEncoded =
                        URLEncoder.encode(TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE, "UTF-8")
                    assertTrue(
                        "Expected grant_type is ${TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but got $grantType.",
                    ) {
                        grantTypeParamValueUrlEncoded == grantType
                    }
                },
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            with(issuer) {
                authorizeWithPreAuthorizationCode(
                    listOf(
                        CredentialIdentifier("eu.europa.ec.eudiw.pid_mso_mdoc"),
                        CredentialIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                    ),
                    PreAuthorizationCode("eyJhbGciOiJSU0EtFYUaBy", "pin"),
                )
            }
        }

    @Test
    fun `(pre-auth code flow) when access token endpoint return nonce then authorized request must be ProofRequired`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                AccessTokenRequestResponse.Success(
                                    accessToken = UUID.randomUUID().toString(),
                                    expiresIn = 3600,
                                    cNonce = "dfghhj34wpCJp",
                                    cNonceExpiresIn = 86400,
                                ),
                            ),
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    },
                ),
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER)
            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val preAuthorizationCode = preAuthCodeFromOffer(offer)

            with(issuer) {
                val authorizedRequest = authorizeWithPreAuthorizationCode(
                    offer.credentials,
                    PreAuthorizationCode(preAuthorizationCode, null),
                ).getOrThrow()

                assertTrue("Token endpoint provides c_nonce but authorized request is not ProofRequired") {
                    authorizedRequest is AuthorizedRequest.ProofRequired
                }
            }
        }

    @Test
    fun `(auth code flow) when access token endpoint return nonce then authorized request must be ProofRequired`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                AccessTokenRequestResponse.Success(
                                    accessToken = UUID.randomUUID().toString(),
                                    expiresIn = 3600,
                                    cNonce = "dfghhj34wpCJp",
                                    cNonceExpiresIn = 86400,
                                ),
                            ),
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    },
                ),
            )
            val offer = credentialOffer(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val issuerState = issuerStateFromOffer(offer)

            with(issuer) {
                val authorizedRequest = pushAuthorizationCodeRequest(
                    offer.credentials,
                    issuerState,
                ).getOrThrow()
                    .handleAuthorizationCode(AuthorizationCode("auth-code"))
                    .requestAccessToken().getOrThrow()

                assertTrue("Token endpoint provides c_nonce but authorized request is not ProofRequired") {
                    authorizedRequest is AuthorizedRequest.ProofRequired
                }
            }
        }

    @Test
    fun `when par endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/ext/par/request", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                PushedAuthorizationRequestResponse.Failure(
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
            val offer = credentialOffer(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val issuerState = issuerStateFromOffer(offer)

            with(issuer) {
                pushAuthorizationCodeRequest(offer.credentials, issuerState)
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
    fun `when token endpoint responds with failure, exception AccessTokenRequestFailed is thrown (auth code flow)`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                AccessTokenRequestResponse.Failure(
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
            val offer = credentialOffer(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val issuerState = issuerStateFromOffer(offer)

            with(issuer) {
                val parPlaced = pushAuthorizationCodeRequest(offer.credentials, issuerState).getOrThrow()
                val authorizationCode = UUID.randomUUID().toString()
                parPlaced
                    .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                    .requestAccessToken()
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
    fun `when token endpoint responds with failure, exception AccessTokenRequestFailed is thrown (pre-auth code flow)`() =
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                oidcWellKnownMocker(),
                parPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/token", HttpMethod.Post),
                    responseBuilder = {
                        respond(
                            content = Json.encodeToString(
                                AccessTokenRequestResponse.Failure(
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
            val offer = credentialOffer(mockedKtorHttpClientFactory, PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER)
            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            val preAuthCode = preAuthCodeFromOffer(offer)

            with(issuer) {
                authorizeWithPreAuthorizationCode(
                    offer.credentials,
                    PreAuthorizationCode(preAuthCode, null),
                )
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

    private suspend fun issuer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialIssuerIdentifier: CredentialIssuerId,
    ): Issuer = ktorHttpClientFactory().use { httpClient ->
        with(httpClient) {
            val issuerMetadata =
                with(CredentialIssuerMetadataResolver) { resolve(credentialIssuerIdentifier) }

            val authServerMetadata = with(AuthorizationServerMetadataResolver) {
                resolve(issuerMetadata.authorizationServers[0]).getOrThrow()
            }

            Issuer.make(
                authorizationServerMetadata = authServerMetadata,
                config = vciWalletConfiguration,
                ktorHttpClientFactory = ktorHttpClientFactory,
                issuerMetadata = issuerMetadata,
            )
        }
    }

    private suspend fun credentialOffer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialOfferStr: String,
    ): CredentialOffer {
        return CredentialOfferRequestResolver(ktorHttpClientFactory = ktorHttpClientFactory)
            .resolve("https://$CredentialIssuer_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()
    }

    private fun issuerStateFromOffer(offer: CredentialOffer): String? {
        val issuerState =
            when (val grants = offer.grants) {
                is Grants.AuthorizationCode -> grants.issuerState
                is Grants.Both -> grants.authorizationCode.issuerState
                null -> null
                else -> fail("Not expected offer grant type")
            }
        return issuerState
    }

    private fun preAuthCodeFromOffer(offer: CredentialOffer): String {
        val preAuthorizationCode =
            when (val grants = offer.grants) {
                is Grants.PreAuthorizedCode -> grants.preAuthorizedCode
                is Grants.Both -> grants.preAuthorizedCode.preAuthorizedCode
                else -> fail("Not expected offer grant type")
            }
        return preAuthorizationCode
    }
}
