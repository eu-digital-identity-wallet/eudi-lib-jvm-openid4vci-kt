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
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.Assertions.fail
import java.io.File
import java.net.URI
import java.net.URL
import java.net.URLEncoder
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as KtorServerContentNegotiation

class IssuanceFlowsTest {

    private val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
    private val AUTHORIZATION_SERVER_PUBLIC_URL = "https://as.example.com"

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

    enum class IssuanceFlow {
        PRE_AUTHORIZED,
        AUTHORIZED_WALLET_INITIATED,
        AUTHORIZED_ISSUER_INITIATED,
    }

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        clientSecret = "23WR66278",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `Successful issuance with authorization code flow (wallet initiated)`() {
        println("[Scenario 1]: ISSUANCE INITIATED FROM WALLET")
        testBed(
            { client ->
                authorizationFlowIssuance(
                    IssuanceFlow.AUTHORIZED_WALLET_INITIATED,
                    createPostPar(client),
                    createGetAccessToken(client),
                    createGetASMetadata(client),
                )
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

        testBed(
            { client ->
                authorizationFlowIssuance(
                    IssuanceFlow.AUTHORIZED_ISSUER_INITIATED,
                    createPostPar(client),
                    createGetAccessToken(client),
                    createGetASMetadata(client),
                )
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
        testBed(
            { client ->
                preAuthorizationFlowIssuance(
                    createPostPar(client),
                    createGetAccessToken(client),
                    createGetASMetadata(client),
                )
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

    private fun authorizationFlowIssuance(
        issuanceFlow: IssuanceFlow,
        postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
        getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
        getAsMetadata: HttpGet<String>,
    ) = runBlocking {
        val credentialOfferStr = when (issuanceFlow) {
            IssuanceFlow.AUTHORIZED_WALLET_INITIATED -> AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS
            IssuanceFlow.AUTHORIZED_ISSUER_INITIATED -> AUTH_CODE_GRANT_CREDENTIAL_OFFER
            IssuanceFlow.PRE_AUTHORIZED -> fail("Wrong test data")
        }

        val offer = CredentialOfferRequestResolver(
            httpGet = getAsMetadata,
        ).resolve(
            "https://localhost:8080/credentialoffer?credential_offer=$credentialOfferStr",
        ).getOrThrow()

        // AUTHORIZATION CODE FLOW IS USED FOR ISSUANCE
        val issuer = AuthorizationCodeFlowIssuer.make(
            IssuanceAuthorizer.make(
                offer.authorizationServerMetadata,
                vciWalletConfiguration,
                postPar,
                getAccessToken,
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
            issuer.placePushedAuthorizationRequest(offer.credentials, issuerState).getOrThrow()
                .also { println(it) }

        // [WALLET] CONSTRUCTS url GET request opens it in browser window and authenticates user in issuer's side
        // [WALLET] EXTRACTS THE AUTHORIZATION CODE FROM ISSUER'S RESPONSE
        val authorizationCode = UUID.randomUUID().toString()

        // Proceed with next steps to issue certificate
        with(issuer) {
            parRequested
                .authorize(authorizationCode).getOrThrow().also { println(it) }
                .placeAccessTokenRequest().getOrThrow().also { println(it) }
                .issueCredential().getOrThrow().also { println(it) }
        }
    }

    private fun preAuthorizationFlowIssuance(
        postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
        getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
        getAsMetadata: HttpGet<String>,
    ) = runBlocking {
        val offer = CredentialOfferRequestResolver(
            httpGet = getAsMetadata,
        ).resolve(
            "https://localhost:8080/credentialoffer?credential_offer=$PRE_AUTH_CODE_GRANT_CREDENTIAL_OFFER",
        ).getOrThrow()

        val issuer = PreAuthorizationCodeFlowIssuer.make(
            IssuanceAuthorizer.make(
                offer.authorizationServerMetadata,
                vciWalletConfiguration,
                postPar,
                getAccessToken,
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
            authorize(preAuthorizationCode, userPin).getOrThrow().also { println(it) }
                .placeAccessTokenRequest().getOrThrow().also { println(it) }
                .issueCredential().getOrThrow().also { println(it) }
        }
    }

    fun testBed(
        testBlock: (client: HttpClient) -> Unit,
        parPostAssertions: (call: ApplicationCall) -> Unit,
        tokenPostAssertions: (call: ApplicationCall) -> Unit,
    ) = testApplication {
        externalServices {
            // Credential issuer server
            hosts(CREDENTIAL_ISSUER_PUBLIC_URL) {
                install(KtorServerContentNegotiation) {
                    json()
                }
                routing {
                    get("/.well-known/openid-credential-issuer") {
                        call.respond(
                            HttpStatusCode.OK,
                            credentialIssuerMetaData(),
                        )
                    }
                }
            }

            // Authorization server
            hosts(AUTHORIZATION_SERVER_PUBLIC_URL) {
                install(KtorServerContentNegotiation) {
                    json()
                }
                routing {
                    get("/.well-known/openid-configuration") {
                        val response = getResourceAsText("authorization-server/well_known_response.json")
                        call.respond(HttpStatusCode.OK, response)
                    }

                    post("/ext/par/request") {
                        parPostAssertions(call)

                        call.respond(
                            HttpStatusCode.OK,
                            PushedAuthorizationRequestResponse.Success(
                                "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                                3600,
                            ),
                        )
                    }

                    post("/token") {
                        tokenPostAssertions(call)

                        call.respond(
                            HttpStatusCode.OK,
                            AccessTokenRequestResponse.Success(
                                accessToken = UUID.randomUUID().toString(),
                                expiresIn = 3600,
                                scope = "UniversityDegree PID_mso_mdoc",
                            ),
                        )
                    }
                }
            }
        }
        val managedHttpClient = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        testBlock(managedHttpClient)
    }

    private fun credentialIssuerMetaData(): CredentialIssuerMetadataObject {
        return CredentialIssuerMetadataObject(
            credentialIssuerIdentifier = CREDENTIAL_ISSUER_PUBLIC_URL,
            authorizationServer = AUTHORIZATION_SERVER_PUBLIC_URL,
            credentialEndpoint = "$CREDENTIAL_ISSUER_PUBLIC_URL/issue",
            credentialsSupported = listOf(
                JsonObject(
                    mapOf(
                        "format" to JsonPrimitive("mso_mdoc"),
                        "scope" to JsonPrimitive("UniversityDegree"),
                        "doctype" to JsonPrimitive("eu.europa.ec.UniversityDegree"),
                    ),
                ),
                JsonObject(
                    mapOf(
                        "format" to JsonPrimitive("mso_mdoc"),
                        "scope" to JsonPrimitive("PID_mso_mdoc"),
                        "doctype" to JsonPrimitive("eu.europa.ec.pid"),
                    ),
                ),
            ),
        )
    }

    private fun createPostPar(managedHttpClient: HttpClient): HttpFormPost<PushedAuthorizationRequestResponse> =
        object : HttpFormPost<PushedAuthorizationRequestResponse> {
            override suspend fun post(
                url: URL,
                formParameters: Map<String, String>,
            ): PushedAuthorizationRequestResponse {
                val response = managedHttpClient.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        formParameters.entries.forEach { append(it.key, it.value) }
                    },
                )
                return if (response.status == HttpStatusCode.OK) {
                    response.body<PushedAuthorizationRequestResponse.Success>()
                } else {
                    response.body<PushedAuthorizationRequestResponse.Failure>()
                }
            }
        }

    private fun createGetAccessToken(managedHttpClient: HttpClient): HttpFormPost<AccessTokenRequestResponse> =
        object : HttpFormPost<AccessTokenRequestResponse> {
            override suspend fun post(url: URL, formParameters: Map<String, String>): AccessTokenRequestResponse {
                val response = managedHttpClient.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        formParameters.entries.forEach { append(it.key, it.value) }
                    },
                )
                return if (response.status == HttpStatusCode.OK) {
                    response.body<AccessTokenRequestResponse.Success>()
                } else {
                    response.body<AccessTokenRequestResponse.Failure>()
                }
            }
        }

    private fun createGetASMetadata(managedHttpClient: HttpClient): HttpGet<String> =
        object : HttpGet<String> {
            override suspend fun get(url: URL): Result<String> = runCatching {
                managedHttpClient.get(url).body<String>()
            }
        }

    private fun getResourceAsText(resource: String): String =
        File(ClassLoader.getSystemResource(resource).path).readText()
}
