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

import eu.europa.ec.eudi.openid4vci.internal.mapError
import java.net.URI
import java.net.URL

/**
 * An abstraction of an HTTP Get operation
 * to obtain [R]
 */
fun interface HttpGet<out R> {
    suspend fun get(url: URL): Result<R>
}

/**
 * An abstraction of an HTTP Post operation with application/x-www-form-urlencoded media type
 * parsing response as [R].
 */
fun interface HttpFormPost<out R> {
    suspend fun post(url: URL, formParameters: Map<String, String>): R
}

/**
 * An abstraction of an HTP Post operation of payload [T] parsing response as [R].
 */
fun interface HttpPost<in T, out R> {
    suspend fun post(url: URL, payload: T): R
}

/**
 * Convenient method for parsing a string into a [URL]
 */
internal fun String.asURL(onError: (Throwable) -> Throwable = { it }): Result<URL> =
    runCatching { URL(this) }.mapError(onError)

/**
 * Convenient method for parsing a string into a [URI]
 */
internal fun String.asURI(onError: (Throwable) -> Throwable = { it }): Result<URI> =
    runCatching { URI(this) }.mapError(onError)
