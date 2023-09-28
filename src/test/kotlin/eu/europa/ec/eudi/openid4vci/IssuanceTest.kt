/*
 *
 *  * Copyright (c) 2023 European Commission
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package eu.europa.ec.eudi.openid4vci

import eu.europa.ec.eudi.openid4vci.internal.AccessTokenRequestResponse
import eu.europa.ec.eudi.openid4vci.internal.PushedAuthorizationRequestResponse
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as KtorServerContentNegotiation
import java.net.URL
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class IssuanceTest {

    enum class IssuanceFlow {
        PRE_AUTHORIZED,
        AUTHORIZED
    }

    @Test
    fun testSenario1() {
        testBed(
            { client ->
                scenario1(createPostPar(client), createGetAccessToken(client))
            },
            { postParCall ->
                runBlocking {
                    val formParameters = postParCall.receiveParameters()
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        postParCall.request.headers["Content-Type"],
                    )
                    val scope = formParameters["scope"].toString()
                    assertTrue(scope.contains("UniversityDegree_JWT"))
                    assertTrue(scope.contains("PID_mso_mdoc"))
                }
            },
            { tokenPostCall ->
                runBlocking {
                    assertEquals(
                        "application/x-www-form-urlencoded; charset=UTF-8",
                        tokenPostCall.request.headers["Content-Type"],
                    )
                }
            }
        )
    }

    @Test
    fun testSenario3() {
        testBed(
            { client ->
                scenario3(createGetAccessToken(client))
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
                    )
                }
            },

        )
    }

    private fun scenario1(
        postPar: HttpFormPost<PushedAuthorizationRequestResponse>,
        getAccessToken: HttpFormPost<AccessTokenRequestResponse>
    ) = runBlocking {
        println("[Scenario 1]: ISSUANCE INITIATED FROM WALLET")

        // PID PROVIDER IS SELECTED FROM USER OR PRE-CONFIGURED IN WALLET
        var credentialIssuerMetaData: CredentialIssuerMetaData = credentialIssuerMetaData()

        // WALLET PREPARES THE CREDENTIAL OFFER TO REQUEST
        var credentialOffer: CredentialOffer = credentialOffer(IssuanceFlow.AUTHORIZED)

        // AUTHORIZATION CODE FLOW IS USED FOR ISSUANCE
        val initiated = AuthCodeFlowIssuance.initFlow(credentialIssuerMetaData, credentialOffer)
            .also { println(it) }

        // Initiate PID Issuance Request
        val parRequested = initiated.placePushedAuthorizationRequest(postPar).getOrThrow()
            .also { println(it) }

        println("PAR Authorize URL: ${parRequested.getAuthorizationCodeURL}")

        // WALLET CONSTRUCTS url GET request opens it in browser window and authenticates user in issuer's side
        // WALLET EXTRACTS THE AUTHORIZATION CODE FROM ISSUER'S RESPONSE
        val authorizationCode = UUID.randomUUID().toString()

        val authorized = parRequested.authorized(authorizationCode).getOrThrow().also { println(it) }

        val tokenRequested = authorized.placeAccessTokenRequest(getAccessToken).getOrThrow().also { println(it) }

        val requestVerifiableCredentialIssuance =
            tokenRequested.requestVerifiableCredentialIssuance(tokenRequested.token) {
                it.certificate != null
            }

        requestVerifiableCredentialIssuance.getOrThrow().also { println(it) }

    }

    private fun scenario3(getAccessToken: HttpFormPost<AccessTokenRequestResponse>) = runBlocking {
        println("[Scenario 3]: ISSUANCE INITIATED FROM ISSUER SITE VIA A CREDENTIAL OFFER")

        // User interacts with issuer's site, authenticates and a credential offer is presented as QR code
        // User scans QR code via wallet scanner
        var credentialOffer: CredentialOffer = credentialOffer(IssuanceFlow.PRE_AUTHORIZED)
        // Wallet retrieves issuer's metadata
        var credentialIssuerMetaData: CredentialIssuerMetaData = credentialIssuerMetaData()

        // PRE-AUTHORIZATION CODE FLOW IS USED FOR ISSUANCE
        val initialState = PreAuthCodeFlowIssuance.initFlow(credentialIssuerMetaData, credentialOffer).also { println(it) }

        // Extract pre-authorized code from offer
        val preAuthorizedCode = (credentialOffer.grants as Grants.PreAuthorizedCode).preAuthorizedCode
        // Pin is passed to wallet
        val pin = "pin"

        val tokenRequested = initialState.placeAccessTokenRequest(
                IssuanceAuthorization.PreAuthorizationCode(preAuthorizedCode, pin),
                getAccessToken,
            ).getOrThrow().also { println(it) }

        val requestVerifiableCredentialIssuance =
            tokenRequested.requestVerifiableCredentialIssuance(tokenRequested.token) {
                it.certificate != null
            }

        requestVerifiableCredentialIssuance.getOrThrow().also { println(it) }
    }


    fun testBed(
        testBlock: (client: HttpClient) -> Unit,
        parPostAssertions: (call: ApplicationCall) -> Unit,
        tokenPostAssertions: (call: ApplicationCall) -> Unit,
    ) = testApplication {
        externalServices {
            hosts("https://as.example.com") {
                install(KtorServerContentNegotiation) {
                    json()
                }
                routing {

                    post("/as/par") {

                        parPostAssertions(call)

                        call.respond(
                            HttpStatusCode.OK,
                            PushedAuthorizationRequestResponse.Success("org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c", 3600)
                        )
                    }

                    post("/token") {

                        tokenPostAssertions(call)

                        call.respond(HttpStatusCode.OK,
                            AccessTokenRequestResponse.Success(
                                accessToken = UUID.randomUUID().toString(),
                                expiresIn = 3600,
                                scope = listOf("UniversityDegree_JWT", "PID_mso_mdoc")
                            )
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

    private fun credentialIssuerMetaData(): CredentialIssuerMetaData {
        return CredentialIssuerMetaData(
            CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
            URL("https://as.example.com"),
            URL("https://credential-issuer.example.com/issue"),
            null,
            null,
            emptyList(),
            emptyList(),
            false,
            emptyList()
        )
    }

    private fun credentialOffer(authorized: IssuanceFlow): CredentialOffer {
        return when (authorized) {
            IssuanceFlow.AUTHORIZED ->
                CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    listOf(
                        Credential.ScopedCredential("UniversityDegree_JWT"),
                        Credential.ScopedCredential("PID_mso_mdoc"),
                    ),
                    Grants.AuthorizationCode("eyJhbGciOiJSU0EtFYUaBy")
                )

            IssuanceFlow.PRE_AUTHORIZED ->
                CredentialOffer(
                    CredentialIssuerId("https://credential-issuer.example.com").getOrThrow(),
                    listOf(Credential.ScopedCredential("UniversityDegree_JWT")),
                    Grants.PreAuthorizedCode("eyJhbGciOiJSU0EtFYUaBy", true)
                )
        }
    }

    private fun createPostPar(managedHttpClient: HttpClient): HttpFormPost<PushedAuthorizationRequestResponse> =
        object : HttpFormPost<PushedAuthorizationRequestResponse> {
            override suspend fun post(
                url: URL,
                formParameters: Map<String, String>
            ): PushedAuthorizationRequestResponse {
                val response = managedHttpClient.submitForm(
                    url = url.toString(),
                    formParameters = Parameters.build {
                        formParameters.entries.forEach { append(it.key, it.value) }
                    },
                )
                return if (response.status == HttpStatusCode.OK)
                    response.body<PushedAuthorizationRequestResponse.Success>()
                else
                    response.body<PushedAuthorizationRequestResponse.Failure>()
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
                return if (response.status == HttpStatusCode.OK)
                    response.body<AccessTokenRequestResponse.Success>()
                else
                    response.body<AccessTokenRequestResponse.Failure>()
            }

        }
}