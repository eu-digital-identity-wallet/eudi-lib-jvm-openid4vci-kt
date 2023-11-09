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

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import java.net.URI

internal typealias HttpRequestDataMatcher = (HttpRequestData) -> Boolean
internal typealias HttpResponseDataBuilder = MockRequestHandleScope.() -> HttpResponseData

/**
 * Gets a [HttpRequestDataMatcher] that matches the provided [url] and [method].
 */
internal fun match(url: URI, method: HttpMethod = HttpMethod.Get): HttpRequestDataMatcher =
    { request -> request.url.toURI() == url && request.method == method }

internal fun endsWithMatch(endsWith: String, method: HttpMethod = HttpMethod.Get): HttpRequestDataMatcher =
    { request -> request.url.encodedPath == endsWith && request.method == method }

/**
 * Gets a [HttpRequestDataMatcher] that matches the provided [url] and [method].
 */
internal fun match(url: String, method: HttpMethod = HttpMethod.Get): HttpRequestDataMatcher =
    match(URI.create(url), method)

/**
 * Gets a [HttpResponseDataBuilder] that returns the provided [resource]
 * as an 'application/json' [HttpResponseData] using the provided [status].
 */
internal fun jsonResponse(resource: String, status: HttpStatusCode = HttpStatusCode.OK): HttpResponseDataBuilder =
    {
        respond(
            content = getResourceAsText(resource),
            status = status,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }

/**
 * Gets a [HttpResponseDataBuilder] that returns '404/Not Found'.
 */
internal fun notFound(): HttpResponseDataBuilder =
    {
        respondError(HttpStatusCode.NotFound)
    }

/**
 * A [requestMatcher] alongside the [responseBuilder] that must be invoked when it matches.
 */
internal data class RequestMocker(
    val requestMatcher: HttpRequestDataMatcher,
    val responseBuilder: HttpResponseDataBuilder,
)

/**
 * Sets up a [MockEngine] using the provided [mocks] and invokes the provided [action].
 * The [HttpGet] implementation provided to [action] is based on the [MockEngine] that was set up.
 * [verifier] can be used to verify the requests that have been performed using the [MockEngine].
 */
internal suspend fun mockEngine(
    vararg mocks: RequestMocker,
    verifier: (List<HttpRequestData>) -> Unit = {},
    action: suspend (HttpGet<String>) -> Unit,
) {
    MockEngine { request ->
        mocks
            .firstOrNull { it.requestMatcher(request) }
            ?.responseBuilder
            ?.invoke(this)
            ?: respondError(HttpStatusCode.NotFound)
    }.use { mockEngine ->
        HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json()
            }
            expectSuccess = true
        }.use { httpClient ->
            val httpGet = HttpGet {
                runCatching {
                    httpClient.get(it).bodyAsText()
                }
            }

            action(httpGet)
            verifier(mockEngine.requestHistory)
        }
    }
}

internal suspend fun mockEngineGeneric(
    vararg mocks: RequestMocker,
    verifier: (List<HttpRequestData>) -> Unit = {},
    action: suspend (client: HttpClient) -> Unit,
) {
    MockEngine { request ->
        mocks
            .firstOrNull { it.requestMatcher(request) }
            ?.responseBuilder
            ?.invoke(this)
            ?: respondError(HttpStatusCode.NotFound)
    }.use { mockEngine ->
        HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json()
            }
            expectSuccess = true
        }.use { client ->
           action(client)
        }
    }
}
