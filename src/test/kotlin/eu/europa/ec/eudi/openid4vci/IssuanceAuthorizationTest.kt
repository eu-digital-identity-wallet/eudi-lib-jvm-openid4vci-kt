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
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions

import java.net.URI
import java.net.URLEncoder
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

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
                    assertThat(
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                        "application/x-www-form-urlencoded; charset=UTF-8".equals(postParCall.request.headers["Content-Type"]),
                    )
                    val scope = formParameters["scope"].toString()
                    assertThat(
                        "Missing scope UniversityDegree",
                        scope.contains("UniversityDegree"),
                    )
                    assertThat(
                        "Missing scope PID_mso_mdoc",
                        scope.contains("PID_mso_mdoc"),
                    )
                    assertThat(
                        "No issuer_state expected when issuance starts from wallet",
                        formParameters["issuer_state"] == null,
                    )

                    assertThat(
                        "PKCE code challenge was expected but not sent.",
                        formParameters["code_challenge"] != null,
                    )
                    assertThat(
                        "PKCE code challenge method was expected but not sent.",
                        formParameters["code_challenge_method"] != null,
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

                    assertThat(
                        "PKCE code verifier was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM] != null,
                    )

                    val grantType = formParameters[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.",
                        grantType != null,
                    )
                    assertThat(
                        "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                        TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE.equals(grantType),
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
                    assertThat(
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                        "application/x-www-form-urlencoded; charset=UTF-8".equals(postParCall.request.headers["Content-Type"]),
                    )
                    val scope = formParameters["scope"].toString()
                    assertThat(
                        "Missing scope UniversityDegree",
                        scope.contains("UniversityDegree"),
                    )
                    assertThat(
                        "Missing scope PID_mso_mdoc",
                        scope.contains("PID_mso_mdoc"),
                    )

                    assertThat(
                        "Parameter issuer_state is expected when issuance starts from issuer site",
                        formParameters["issuer_state"] != null,
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
                    assertThat(
                        "PKCE code verifier was expected but not sent.",
                        formParameters["code_verifier"] != null,
                    )

                    assertThat(
                        "PKCE code verifier was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM] != null,
                    )

                    val grantType = formParameters[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                    assertThat(
                        "Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.",
                        grantType != null,
                    )
                    assertThat(
                        "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                        TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE.equals(grantType),
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
                    assertThat(
                        "Wrong content-type, expected application/x-www-form-urlencoded",
                        "application/x-www-form-urlencoded; charset=UTF-8".equals(tokenPostCall.request.headers["Content-Type"]),
                    )

                    assertThat(
                        "PKCE code verifier was not expected but sent.",
                        formParameters["code_verifier"] == null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM] != null,
                    )

                    assertThat(
                        "Parameter ${TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM} was expected but not sent.",
                        formParameters[TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM] != null,
                    )

                    val grantType = formParameters[TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM]
                    assertThat(
                        "Parameter grant_type was expected but not sent.",
                        grantType != null,
                    )
                    val grantTypeParamValueUrlEncoded =
                        URLEncoder.encode(TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE, "UTF-8")
                    assertThat(
                        "Expected grant_type is ${TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                        grantTypeParamValueUrlEncoded.equals(grantType),
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
        ).resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr").getOrThrow()

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
                else -> Assertions.fail("Not expected offer grant type")
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
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode)).also { println(it) }
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
