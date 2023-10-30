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
import io.ktor.server.request.*
import kotlinx.coroutines.runBlocking
import java.net.URI
import java.net.URLEncoder
import java.util.*
import kotlin.test.*

class IssuanceAuthorizationTest {

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["PID_mso_mdoc", "UniversityDegree"],
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
          "credentials": ["PID_mso_mdoc", "UniversityDegree"]          
        }
    """.trimIndent()

    private val PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["PID_mso_mdoc", "UniversityDegree"],
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
    fun `Successful issuance with authorization code flow (wallet initiated)`() {
        println("[Scenario 1]: ISSUANCE INITIATED FROM WALLET")

        authorizationTestBed(
            { client ->
                authFlowTestBlock(AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS, client)
            },
            { postParCall ->
                runBlocking {
                    val formParameters = postParCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        postParCall.request.headers["Content-Type"],
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                    )
                    val scope = formParameters["scope"].toString()
                    assertTrue(
                        scope.contains("UniversityDegree"),
                        "Missing scope UniversityDegree",
                    )
                    assertTrue(
                        scope.contains("PID_mso_mdoc"),
                        "Missing scope PID_mso_mdoc",
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
                }
            },
            { tokenPostCall ->
                runBlocking {
                    val formParameters = tokenPostCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        tokenPostCall.request.headers["Content-Type"],
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
                }
            },
        )
    }

    @Test
    fun `Successful issuance with authorization code flow (initiated from issuer site)`() {
        println("[Scenario 2]: ISSUANCE INITIATED FROM ISSUER SITE")

        authorizationTestBed(
            { client ->
                authFlowTestBlock(AUTH_CODE_GRANT_CREDENTIAL_OFFER, client)
            },
            { postParCall ->
                runBlocking {
                    val formParameters = postParCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        postParCall.request.headers["Content-Type"],
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                    )
                    val scope = formParameters["scope"].toString()
                    assertTrue(
                        scope.contains("UniversityDegree"),
                        "Missing scope UniversityDegree",
                    )
                    assertTrue(
                        scope.contains("PID_mso_mdoc"),
                        "Missing scope PID_mso_mdoc",
                    )

                    assertNotNull(
                        formParameters["issuer_state"],
                        "Parameter issuer_state is expected when issuance starts from issuer site",
                    )
                }
            },
            { tokenPostCall ->
                runBlocking {
                    val formParameters = tokenPostCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        tokenPostCall.request.headers["Content-Type"],
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
                }
            },
        )
    }

    @Test
    fun `Successful issuance with pre-authorization code flow`() {
        println("[Scenario 3]: ISSUANCE INITIATED FROM ISSUER SITE VIA A CREDENTIAL OFFER")

        authorizationTestBed(
            { client ->
                preAuthFlowTestBlock(PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER, client)
            },
            { postParCall ->
                fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
            },
            { tokenPostCall ->
                runBlocking {
                    val formParameters = tokenPostCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        tokenPostCall.request.headers["Content-Type"],
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
                }
            },
        )
    }

    private fun authFlowTestBlock(
        credentialOfferStr: String,
        client: HttpClient,
    ) = runBlocking {
        val offer = CredentialOfferRequestResolver(
            httpGet = createGetASMetadata(client),
        ).resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()

        // AUTHORIZATION CODE FLOW IS USED FOR ISSUANCE
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

        val issuerState =
            when (val grants = offer.grants) {
                is Grants.AuthorizationCode -> grants.issuerState
                is Grants.Both -> grants.authorizationCode.issuerState
                null -> null
                else -> fail("Not expected offer grant type")
            }

        // Place PAR
        val parRequested =
            issuer.pushAuthorizationCodeRequest(offer.credentials, issuerState).getOrThrow()
                .also { println(it) }

        // [WALLET] CONSTRUCTS url GET request opens it in browser window and authenticates user in issuer's side
        // [WALLET] EXTRACTS THE AUTHORIZATION CODE FROM ISSUER'S RESPONSE
        val authorizationCode = UUID.randomUUID().toString()

        // Proceed with next steps to issue certificate
        with(issuer) {
            parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .also { println(it) }
                .requestAccessToken().getOrThrow().also { println(it) }
        }
    }

    private fun preAuthFlowTestBlock(
        credentialOfferStr: String,
        client: HttpClient,
    ) = runBlocking {
        val offer = CredentialOfferRequestResolver(
            httpGet = createGetASMetadata(client),
        ).resolve(
            "https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr",
        ).getOrThrow()

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

        val preAuthorizationCode =
            when (val grants = offer.grants) {
                is Grants.PreAuthorizedCode -> grants.preAuthorizedCode
                is Grants.Both -> grants.preAuthorizedCode.preAuthorizedCode
                else -> fail("Not expected offer grant type")
            }
        val userPin = "pin"

        with(issuer) {
            authorizeWithPreAuthorizationCode(
                offer.credentials,
                IssuanceAuthorization.PreAuthorizationCode(preAuthorizationCode, userPin),
            ).getOrThrow().also { println(it) }
        }
    }
}
