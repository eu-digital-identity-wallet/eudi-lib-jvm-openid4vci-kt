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
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.serialization.json.Json

/**
 * Implementation of [IssuanceRequester] that used ktor clients for all http calls.
 */
@Suppress("ktlint")
internal class KtorIssuanceRequester(
    override val issuerMetadata: CredentialIssuerMetadata,
    val coroutineDispatcher: CoroutineDispatcher,
    val ktorHttpClientFactory: KtorHttpClientFactory = HttpClientFactory,
) : IssuanceRequester {

    override suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential
    ): Result<CredentialIssuanceResponse> =
        ktorHttpClientFactory().use { client -> requester(client).placeIssuanceRequest(accessToken, request) }

    override suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials
    ): Result<CredentialIssuanceResponse> =
        ktorHttpClientFactory().use { client -> requester(client).placeBatchIssuanceRequest(accessToken, request) }

    override suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        transactionId: TransactionId,
    ): Result<DeferredCredentialIssuanceResponse> =
        ktorHttpClientFactory().use { client -> requester(client).placeDeferredCredentialRequest(accessToken, transactionId) }

    private fun requester(client: HttpClient): DefaultIssuanceRequester =
        DefaultIssuanceRequester(
            coroutineDispatcher = coroutineDispatcher,
            issuerMetadata = issuerMetadata,
            postIssueRequest = postIssuanceRequest(client),
            postDeferredIssueRequest = postDeferredIssuanceRequest(client),
        )

    companion object {
        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val HttpClientFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = Json { ignoreUnknownKeys = true },
                    )
                }
            }
        }
    }
}

private fun postIssuanceRequest(httpClient: HttpClient):
    HttpPost<CredentialIssuanceRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse> =
    HttpPost { url, headers, payload, responseHandler ->
        val response = httpClient.post(url) {
            headers {
                headers.forEach { (k, v) -> append(k, v) }
            }
            contentType(ContentType.parse("application/json"))
            setBody(payload)
        }
        responseHandler(response)
    }

private fun postDeferredIssuanceRequest(httpClient: HttpClient):
    HttpPost<DeferredIssuanceRequestTO, DeferredCredentialIssuanceResponse, DeferredCredentialIssuanceResponse> =
    HttpPost { url, headers, payload, responseHandler ->
        val response = httpClient.post(url) {
            headers {
                headers.forEach { (k, v) -> append(k, v) }
            }
            contentType(ContentType.parse("application/json"))
            setBody(payload)
        }
        responseHandler(response)
    }
