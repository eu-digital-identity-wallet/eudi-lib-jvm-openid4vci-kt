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
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json

typealias KtorHttpClientFactory = () -> HttpClient

/**
 * Factory which produces a [Ktor Http client][HttpClient]
 * The actual engine will be peeked up by whatever
 * it is available in classpath
 *
 * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
 */
val DefaultHttpClientFactory: KtorHttpClientFactory = {
    HttpClient {
        install(ContentNegotiation) {
            json(
                json = Json { ignoreUnknownKeys = true },
            )
        }
    }
}
