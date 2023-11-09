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

import eu.europa.ec.eudi.openid4vci.internal.issuance.TokenEndpointForm
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.net.URLEncoder
import java.util.*
import kotlin.test.*

class IssuanceAuthorizationTest {

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
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
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"]          
        }
    """.trimIndent()

    private val PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc", "eu.europa.ec.eudiw.pid_vc_sd_jwt"],
          "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
              "pre-authorized_code": "eyJhbGciOiJSU0EtFYUaBy",
              "user_pin_required": true
            }
          }
        }
    """.trimIndent()

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `successful authorization with authorization code flow (wallet initiated)`() {
        authorizationTestBed(
            { client ->
                authFlowTestBlock(AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS, client)
            },
            { call ->
                runTest {
                    val formParameters = call.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        call.request.headers["Content-Type"],
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                    )
                    val scope = formParameters["scope"].toString()
                    assertTrue(
                        scope.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                        "Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt",
                    )
                    assertTrue(
                        scope.contains("eu.europa.ec.eudiw.pid_mso_mdoc"),
                        "Missing scope eu.europa.ec.eudiw.pid_mso_mdoc",
                    )
                    assertNull(
                        formParameters["issuer_state"],
                        "No issuer_state expected when issuance starts from wallet",
                    )

                    assertNotNull(
                        formParameters["code_challenge"],
                        "PKCE code challenge was expected but not sent.",
                    )
                    assertNotNull(
                        formParameters["code_challenge_method"],
                        "PKCE code challenge method was expected but not sent.",
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    val formParameters = call.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        call.request.headers["Content-Type"],
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM],
                        "PKCE code verifier was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.",
                    )

                    val grantType = formParameters[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertNotNull(
                        grantType,
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.",
                    )
                    assertEquals(
                        TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE,
                        grantType,
                        "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        AccessTokenRequestResponse.Success(
                            accessToken = UUID.randomUUID().toString(),
                            expiresIn = 3600,
                        ),
                    )
                }
            },
        )
    }

    @Test
    fun `successful authorization with authorization code flow (initiated from issuer site)`() {
        authorizationTestBed(
            { client ->
                authFlowTestBlock(AUTH_CODE_GRANT_CREDENTIAL_OFFER, client)
            },
            { call ->
                runTest {
                    val formParameters = call.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        call.request.headers["Content-Type"],
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                    )
                    val scope = formParameters["scope"].toString()
                    assertTrue(
                        scope.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                        "Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt",
                    )
                    assertTrue(
                        scope.contains("eu.europa.ec.eudiw.pid_mso_mdoc"),
                        "Missing scope eu.europa.ec.eudiw.pid_mso_mdoc",
                    )

                    assertNotNull(
                        formParameters["issuer_state"],
                        "Parameter issuer_state is expected when issuance starts from issuer site",
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    val formParameters = call.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        call.request.headers["Content-Type"],
                    )
                    assertNotNull(
                        formParameters["code_verifier"],
                        "PKCE code verifier was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM],
                        "PKCE code verifier was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM],
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.",
                    )

                    val grantType = formParameters[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertNotNull(
                        grantType,
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.",
                    )
                    assertEquals(
                        TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE,
                        grantType,
                        "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        AccessTokenRequestResponse.Success(
                            accessToken = UUID.randomUUID().toString(),
                            expiresIn = 3600,
                        ),
                    )
                }
            },
        )
    }

    @Test
    fun `successful authorization with pre-authorization code flow`() {
        authorizationTestBed(
            { client ->
                preAuthFlowTestBlock(PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER, client)
            },
            {
                fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
            },
            { call ->
                runTest {
                    val formParameters = call.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        call.request.headers["Content-Type"],
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                    )

                    assertNull(
                        formParameters["code_verifier"],
                        "PKCE code verifier was not expected but sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM],
                        "Parameter ${TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM} was expected but not sent.",
                    )

                    assertNotNull(
                        formParameters[TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM],
                        "Parameter ${TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM} was expected but not sent.",
                    )

                    val grantType = formParameters[TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM]
                    assertNotNull(
                        grantType,
                        "Parameter grant_type was expected but not sent.",
                    )
                    val grantTypeParamValueUrlEncoded =
                        URLEncoder.encode(TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE, "UTF-8")
                    assertEquals(
                        grantTypeParamValueUrlEncoded,
                        grantType,
                        "Expected grant_type is ${TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                    )

                    call.respond(
                        HttpStatusCode.OK,
                        AccessTokenRequestResponse.Success(
                            accessToken = UUID.randomUUID().toString(),
                            expiresIn = 3600,
                        ),
                    )
                }
            },
        )
    }

    @Test
    fun `(pre-auth code flow) when access token endpoint return nonce then authorized request must be ProofRequired`() {
        authorizationTestBed(
            { client ->
                runTest {
                    val offer = credentialOffer(client, PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER)
                    val issuer = issuer(offer, client)
                    val preAuthorizationCode = preAuthCodeFromOffer(offer)

                    with(issuer) {
                        val authorizedRequest = authorizeWithPreAuthorizationCode(
                            offer.credentials,
                            IssuanceAuthorization.PreAuthorizationCode(preAuthorizationCode, null),
                        ).getOrThrow()

                        assertTrue("Token endpoint provides c_nonce but authorized request is not ProofRequired") {
                            authorizedRequest is AuthorizedRequest.ProofRequired
                        }
                    }
                }
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        AccessTokenRequestResponse.Success(
                            accessToken = UUID.randomUUID().toString(),
                            expiresIn = 3600,
                            cNonce = "dfghhj34wpCJp",
                            cNonceExpiresIn = 86400,
                        ),
                    )
                }
            },
        )
    }

    @Test
    fun `(auth code flow) when access token endpoint return nonce then authorized request must be ProofRequired`() {
        authorizationTestBed(
            { client ->
                runTest {
                    val offer = credentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
                    val issuer = issuer(offer, client)
                    val issuerState = issuerStateFromOffer(offer)

                    with(issuer) {
                        val authorizedRequest = pushAuthorizationCodeRequest(
                            offer.credentials,
                            issuerState,
                        ).getOrThrow()
                            .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode("auth-code"))
                            .requestAccessToken().getOrThrow()

                        assertTrue("Token endpoint provides c_nonce but authorized request is not ProofRequired") {
                            authorizedRequest is AuthorizedRequest.ProofRequired
                        }
                    }
                }
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        AccessTokenRequestResponse.Success(
                            accessToken = UUID.randomUUID().toString(),
                            expiresIn = 3600,
                            cNonce = "dfghhj34wpCJp",
                            cNonceExpiresIn = 86400,
                        ),
                    )
                }
            },
        )
    }

    @Test
    fun `when par endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown`() {
        authorizationTestBed(
            { client ->
                runTest {
                    val offer = credentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
                    val issuer = issuer(offer, client)
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
            },
            { call ->
                runTest {
                    call.respondText(
                        """
                            {
                               "error": "invalid_request",
                               "error_description": "The redirect_uri is not valid for the given client"
                             }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
            {},
        )
    }

    @Test
    fun `when token endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown (auth code flow)`() {
        authorizationTestBed(
            { client ->
                runTest {
                    val offer = credentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER)
                    val issuer = issuer(offer, client)
                    val issuerState = issuerStateFromOffer(offer)

                    with(issuer) {
                        val parPlaced = pushAuthorizationCodeRequest(offer.credentials, issuerState).getOrThrow()
                        val authorizationCode = UUID.randomUUID().toString()
                        parPlaced
                            .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
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
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    call.respondText(
                        """
                            {
                               "error": "unauthorized_client"
                            }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    @Test
    fun `when token endpoint responds with failure, exception PushedAuthorizationRequestFailed is thrown (pre-auth code flow)`() {
        authorizationTestBed(
            { client ->
                runTest {
                    val offer = credentialOffer(client, PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER)
                    val issuer = issuer(offer, client)
                    val preAuthCode = preAuthCodeFromOffer(offer)

                    with(issuer) {
                        authorizeWithPreAuthorizationCode(
                            offer.credentials,
                            IssuanceAuthorization.PreAuthorizationCode(preAuthCode, null),
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
            },
            { call ->
                runTest {
                    call.respond(
                        HttpStatusCode.OK,
                        PushedAuthorizationRequestResponse.Success(
                            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                            3600,
                        ),
                    )
                }
            },
            { call ->
                runTest {
                    call.respondText(
                        """
                            {
                               "error": "unauthorized_client"
                            }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    private fun authFlowTestBlock(
        credentialOfferStr: String,
        client: HttpClient,
    ) = runTest {
        val offer = credentialOffer(client, credentialOfferStr)
        val issuer = issuer(offer, client)
        val issuerState = issuerStateFromOffer(offer)

        with(issuer) {
            val parRequested =
                pushAuthorizationCodeRequest(offer.credentials, issuerState).getOrThrow()
                    .also { println(it) }

            val authorizationCode = UUID.randomUUID().toString()

            parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .also { println(it) }
                .requestAccessToken().getOrThrow().also { println(it) }
        }
    }

    private fun preAuthFlowTestBlock(
        credentialOfferStr: String,
        client: HttpClient,
    ) = runTest {
        val offer = credentialOffer(client, credentialOfferStr)
        val issuer = issuer(offer, client)
        val preAuthorizationCode = preAuthCodeFromOffer(offer)
        val userPin = "pin"

        with(issuer) {
            authorizeWithPreAuthorizationCode(
                offer.credentials,
                IssuanceAuthorization.PreAuthorizationCode(preAuthorizationCode, userPin),
            ).getOrThrow().also { println(it) }
        }
    }

    private suspend fun credentialOffer(
        client: HttpClient,
        credentialOfferStr: String,
    ): CredentialOffer {
        val offer = CredentialOfferRequestResolver(
            httpGet = createGetASMetadata(client),
        ).resolve(
            "https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr",
        ).getOrThrow()
        return offer
    }

    private fun issuer(
        offer: CredentialOffer,
        client: HttpClient,
    ): Issuer {
        val issuer = Issuer.make(
            IssuanceAuthorizer.make(
                offer.authorizationServerMetadata,
                vciWalletConfiguration,
                createPostPar(client),
                createGetAccessToken(client),
            ),
            IssuanceRequester.make(
                issuerMetadata = offer.credentialIssuerMetadata,
                postIssueRequest = createPostIssuance(client),
            ),
        )
        return issuer
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
