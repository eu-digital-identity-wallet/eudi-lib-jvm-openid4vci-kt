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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuerMetadataJsonParser
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.coroutineScope

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
internal class DefaultCredentialIssuerMetadataResolver(
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> = coroutineScope {
        runCatching {
            val credentialIssuerMetadataContent = try {
                val url =
                    URLBuilder(issuer.toString())
                        .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
                        .build()
                        .toURI()
                        .toURL()

                ktorHttpClientFactory().use { client -> client.get(url).body<String>() }
            } catch (t: Throwable) {
                throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
            }
            val metaData = CredentialIssuerMetadataJsonParser.parseMetaData(credentialIssuerMetadataContent)
            if (metaData.credentialIssuerIdentifier != issuer) {
                throw InvalidCredentialIssuerId(
                    IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                )
            }
            metaData
        }
    }
}
