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

import eu.europa.ec.eudi.openid4vci.formats.CredentialIssuanceRequestTO
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.testing.*
import java.util.*

const val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
const val AUTHORIZATION_SERVER_PUBLIC_URL = "https://auth-server.example.com"

fun authorizationTestBed(
    testBlock: (client: HttpClient) -> Unit,
    parPostAssertions: (call: ApplicationCall) -> Unit,
    tokenPostAssertions: (call: ApplicationCall) -> Unit,
) {
    testBed(
        testBlock = testBlock,
        parPostAssertions = parPostAssertions,
        tokenPostAssertions = tokenPostAssertions,
    )
}

fun issuanceTestBed(
    testBlock: suspend (client: HttpClient) -> Unit,
    issuanceRequestAssertions: suspend (call: ApplicationCall) -> Unit,
    encryptedResponses: Boolean = false,
) {
    testBed(
        testBlock = testBlock,
        issuanceRequestAssertions = issuanceRequestAssertions,
        encryptedResponses = encryptedResponses,
    )
}

private fun testBed(
    testBlock: suspend (client: HttpClient) -> Unit,
    parPostAssertions: suspend (call: ApplicationCall) -> Unit = { defaultParPostAssertions(it) },
    tokenPostAssertions: suspend (call: ApplicationCall) -> Unit = { defaultTokenPostAssertions(it) },
    issuanceRequestAssertions: suspend (call: ApplicationCall) -> Unit = {},
    encryptedResponses: Boolean = false,
) = testApplication {
    externalServices {
        // Credential issuer server
        hosts(CREDENTIAL_ISSUER_PUBLIC_URL) {
            install(ContentNegotiation) {
                json()
            }
            routing {
                get("/.well-known/openid-credential-issuer") {
                    val response =
                        if (encryptedResponses)
                            getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json")
                        else
                            getResourceAsText("well-known/openid-credential-issuer_no_encryption.json")

                    call.respond(HttpStatusCode.OK, response)
                }

                post("/credentials") {
                    issuanceRequestAssertions(call)
                }

                post("/credentials/batch") {
                    issuanceRequestAssertions(call)
                }

                post("/credentials/deferred") {
                    issuanceRequestAssertions(call)
                }
            }
        }
    }

    externalServices {
        // Authorization server
        hosts(AUTHORIZATION_SERVER_PUBLIC_URL) {
            install(ContentNegotiation) {
                json()
            }
            routing {
                get("/.well-known/openid-configuration") {
                    call.respond(HttpStatusCode.OK, getResourceAsText("well-known/openid-configuration.json"))
                }

                post("/ext/par/request") {
                    parPostAssertions(call)
                }

                post("/token") {
                    tokenPostAssertions(call)
                }
            }
        }
    }

    val managedHttpClient = createClient {
        install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) { json() }
    }

    testBlock(managedHttpClient)
}

suspend inline fun defaultParPostAssertions(call: ApplicationCall): Unit =
    call.respond(
        HttpStatusCode.OK,
        PushedAuthorizationRequestResponse.Success(
            "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
            3600,
        ),
    )

suspend inline fun defaultTokenPostAssertions(call: ApplicationCall): Unit =
    call.respond(
        HttpStatusCode.OK,
        AccessTokenRequestResponse.Success(
            accessToken = UUID.randomUUID().toString(),
            expiresIn = 3600,
        ),
    )

fun createPostPar(managedHttpClient: HttpClient): HttpFormPost<PushedAuthorizationRequestResponse> =
    HttpFormPost { url, formParameters ->
        val response = managedHttpClient.submitForm(
            url = url.toString(),
            formParameters = Parameters.build {
                formParameters.entries.forEach { append(it.key, it.value) }
            },
        )
        if (response.status == HttpStatusCode.OK) {
            response.body<PushedAuthorizationRequestResponse.Success>()
        } else {
            response.body<PushedAuthorizationRequestResponse.Failure>()
        }
    }

fun createGetAccessToken(managedHttpClient: HttpClient): HttpFormPost<AccessTokenRequestResponse> =
    HttpFormPost { url, formParameters ->
        val response = managedHttpClient.submitForm(
            url = url.toString(),
            formParameters = Parameters.build {
                formParameters.entries.forEach { append(it.key, it.value) }
            },
        )
        if (response.status.isSuccess()) {
            response.body<AccessTokenRequestResponse.Success>()
        } else {
            response.body<AccessTokenRequestResponse.Failure>()
        }
    }

fun createGetASMetadata(managedHttpClient: HttpClient): HttpGet<String> =
    HttpGet { managedHttpClient.get(it).body<String>() }

fun createPostIssuance(
    managedHttpClient: HttpClient,
): HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse> =
    HttpPost { url, headers, payload, responseHandler ->
        val response = managedHttpClient.post(url) {
            headers {
                headers.forEach {
                    append(it.key, it.value)
                }
            }
            contentType(ContentType.parse("application/json"))
            setBody(payload)
        }
        responseHandler(response)
    }

fun createPostDeferredIssuance(
    managedHttpClient: HttpClient,
): HttpPost<DeferredIssuanceRequestTO, DeferredCredentialIssuanceResponse, DeferredCredentialIssuanceResponse> =
    HttpPost { url, headers, payload, responseHandler ->
        val response = managedHttpClient.post(url) {
            headers {
                headers.forEach {
                    append(it.key, it.value)
                }
            }
            contentType(ContentType.parse("application/json"))
            setBody(payload)
        }
        responseHandler(response)
    }
