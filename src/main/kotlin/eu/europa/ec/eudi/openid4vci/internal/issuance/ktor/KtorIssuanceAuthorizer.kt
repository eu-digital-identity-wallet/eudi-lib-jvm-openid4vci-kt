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
package eu.europa.ec.eudi.openid4vci.internal.issuance.ktor

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceAuthorizer
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.serialization.json.Json
import java.net.URL

/**
 * Implementation of [IssuanceAuthorizer] that used ktor clients for all http calls.
 */
internal class KtorIssuanceAuthorizer(
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
    val config: WalletOpenId4VCIConfig,
    val coroutineDispatcher: CoroutineDispatcher,
) : IssuanceAuthorizer {

    override suspend fun submitPushedAuthorizationRequest(
        scopes: List<Scope>,
        state: String,
        issuerState: String?,
    ): Result<Pair<PKCEVerifier, GetAuthorizationCodeURL>> =
        HttpClientFactory().use { client ->
            authorizer(client).submitPushedAuthorizationRequest(scopes, state, issuerState)
        }

    override suspend fun requestAccessTokenAuthFlow(authorizationCode: String, codeVerifier: String): Result<Pair<String, CNonce?>> =
        HttpClientFactory().use { client ->
            authorizer(client).requestAccessTokenAuthFlow(authorizationCode, codeVerifier)
        }

    override suspend fun requestAccessTokenPreAuthFlow(preAuthorizedCode: String, pin: String?): Result<Pair<String, CNonce?>> =
        HttpClientFactory().use { client ->
            authorizer(client).requestAccessTokenPreAuthFlow(preAuthorizedCode, pin)
        }

    private fun authorizer(client: HttpClient) =
        DefaultIssuanceAuthorizer(
            coroutineDispatcher = coroutineDispatcher,
            authorizationServerMetadata = authorizationServerMetadata,
            config = config,
            postPar = parFormPost(client),
            getAccessToken = accessTokenFormPost(client),
        )

    companion object {

        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        private val HttpClientFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = Json { ignoreUnknownKeys = true },
                    )
                }
            }
        }

        private fun parFormPost(httpClient: HttpClient): HttpFormPost<PushedAuthorizationRequestResponse> =
            object : HttpFormPost<PushedAuthorizationRequestResponse> {
                override suspend fun post(
                    url: URL,
                    formParameters: Map<String, String>,
                ): PushedAuthorizationRequestResponse {
                    val response = httpClient.submitForm(
                        url = url.toString(),
                        formParameters = Parameters.build {
                            formParameters.entries.forEach { append(it.key, it.value) }
                        },
                    )
                    return if (response.status.isSuccess()) {
                        response.body<PushedAuthorizationRequestResponse.Success>()
                    } else {
                        response.body<PushedAuthorizationRequestResponse.Failure>()
                    }
                }
            }

        private fun accessTokenFormPost(httpClient: HttpClient): HttpFormPost<AccessTokenRequestResponse> =
            object : HttpFormPost<AccessTokenRequestResponse> {
                override suspend fun post(url: URL, formParameters: Map<String, String>): AccessTokenRequestResponse {
                    val response = httpClient.submitForm(
                        url = url.toString(),
                        formParameters = Parameters.build {
                            formParameters.entries.forEach { append(it.key, it.value) }
                        },
                    )
                    return if (response.status.isSuccess()) {
                        response.body<AccessTokenRequestResponse.Success>()
                    } else {
                        response.body<AccessTokenRequestResponse.Failure>()
                    }
                }
            }
    }
}
