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
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import java.net.URI

internal typealias HttpRequestDataMatcher = (HttpRequestData) -> Boolean
internal typealias HttpResponseDataBuilder = MockRequestHandleScope.(request: HttpRequestData?) -> HttpResponseData

/**
 * Gets a [HttpRequestDataMatcher] that matches the provided [url] and [method].
 */
internal fun match(url: URI, method: HttpMethod = HttpMethod.Get): HttpRequestDataMatcher =
    { request -> request.url.toURI() == url && request.method == method }

internal fun endsWith(endsWith: String, method: HttpMethod = HttpMethod.Get): HttpRequestDataMatcher =
    { request -> request.url.encodedPath.endsWith(endsWith) && request.method == method }

/**
 * Gets a [HttpResponseDataBuilder] that returns the provided [resource]
 * as an 'application/json' [HttpResponseData] using the provided [status].
 */
internal fun jsonResponse(
    resource: String,
    acceptContentTypes: List<String> = listOf("application/json"),
    status: HttpStatusCode = HttpStatusCode.OK,
): HttpResponseDataBuilder = {
    respond(
        content = getResourceAsText(resource),
        status = status,
        headers = headersOf(
            *acceptContentTypes.map { HttpHeaders.ContentType to listOf(it) }.toTypedArray(),
        ),
    )
}

/**
 * A [requestMatcher] alongside the [responseBuilder] that must be invoked when it matches.
 */
internal data class RequestMocker(
    val requestMatcher: HttpRequestDataMatcher,
    val responseBuilder: HttpResponseDataBuilder,
    val requestValidator: (request: HttpRequestData) -> Unit = {},
)

/**
 * Factory method to create mocked http clients. Http clients behavior is based on the passed [requestMockers].
 */
internal fun mockedHttpClient(
    vararg requestMockers: RequestMocker,
    expectSuccessOnly: Boolean = false,
): HttpClient =
    HttpClient(MockEngine) {
        engine {
            this.addHandler { request ->
                requestMockers
                    .firstOrNull { it.requestMatcher(request) }
                    ?.apply {
                        requestValidator(request)
                    }
                    ?.responseBuilder?.invoke(this, request)
                    ?: respondError(HttpStatusCode.NotFound)
            }
        }
        install(ContentNegotiation) {
            json(
                json = Json { ignoreUnknownKeys = true },
            )
        }
        expectSuccess = expectSuccessOnly
    }
