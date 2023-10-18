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
import eu.europa.ec.eudi.openid4vci.internal.issuance.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.serialization.json.Json
import java.net.URL

/**
 * Implementation of [IssuanceRequester] that used ktor clients for all http calls.
 */
@Suppress("ktlint")
internal class KtorIssuanceRequester private constructor(
    val delegate: IssuanceRequester,
) : IssuanceRequester {

    override val issuerMetadata: CredentialIssuerMetadata
        get() = delegate.issuerMetadata

    override suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential
    ): Result<IssuanceResponse.Single> =
        delegate.placeIssuanceRequest(accessToken, request)

    override suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials
    ): Result<IssuanceResponse.Batch> =
        delegate.placeBatchIssuanceRequest(accessToken, request)

    override suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        request: DeferredCredentialRequest
    ): IssuanceResponse.Single =
        delegate.placeDeferredCredentialRequest(accessToken, request)

    companion object {

        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val DefaultFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = Json { ignoreUnknownKeys = true },
                    )
                }
                expectSuccess = true
            }
        }

        operator fun invoke(
            issuerMetadata: CredentialIssuerMetadata,
            coroutineDispatcher: CoroutineDispatcher,
            httpClientFactory: KtorHttpClientFactory,
        ): KtorIssuanceRequester {
            val client = httpClientFactory()
            val delegate = DefaultIssuanceRequester(
                coroutineDispatcher = coroutineDispatcher,
                issuerMetadata = issuerMetadata,
                postIssueRequest = postIssueRequest(client),
            )
            return KtorIssuanceRequester(delegate)
        }

        private fun postIssueRequest(httpClient: HttpClient):
                HttpPost<CredentialRequestTO, IssuanceResponse.Single, IssuanceResponse.Single> =

            object : HttpPost<CredentialRequestTO, IssuanceResponse.Single, IssuanceResponse.Single> {
                override suspend fun post(
                    url: URL,
                    headers: Map<String, String>,
                    payload: CredentialRequestTO,
                    transform: suspend (response: HttpResponse) -> IssuanceResponse.Single
                ): IssuanceResponse.Single {
                    val response = httpClient.post(url) {
                        headers {
                            headers.forEach {
                                append(it.key, it.value)
                            }
                        }
                        contentType(ContentType.parse("application/json"))
                        setBody(payload)
                    }
                    return transform(response)
                }
            }
    }
}
