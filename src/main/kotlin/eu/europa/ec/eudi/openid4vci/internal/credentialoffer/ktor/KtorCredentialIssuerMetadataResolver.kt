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
package eu.europa.ec.eudi.openid4vci.internal.credentialoffer.ktor

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialIssuerMetadataResolver
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.serialization.json.Json

internal class KtorCredentialIssuerMetadataResolver(
    val coroutineDispatcher: CoroutineDispatcher,
    val ktorHttpClientFactory: KtorHttpClientFactory = HttpClientFactory,
) : CredentialIssuerMetadataResolver {
    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> =
        ktorHttpClientFactory().use { client ->
            resolver(client).resolve(issuer)
        }

    private fun resolver(client: HttpClient) =
        DefaultCredentialIssuerMetadataResolver(
            coroutineDispatcher = coroutineDispatcher,
            httpGet = httpGet(client),
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

        private fun httpGet(httpClient: HttpClient): HttpGet<String> =
            HttpGet {
                runCatching {
                    httpClient.get(it).body<String>()
                }
            }
    }
}
