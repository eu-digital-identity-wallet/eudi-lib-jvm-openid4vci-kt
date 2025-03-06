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
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

internal class DefaultCredentialIssuerMetadataResolver(
    private val httpClient: HttpClient,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(
        issuer: CredentialIssuerId,
        policy: IssuerMetadataPolicy,
    ): Result<CredentialIssuerMetadata> = runCatching {
        val wellKnownUrl = issuer.wellKnown()
        val json = try {
            httpClient.get(wellKnownUrl).body<String>()
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
        }

        CredentialIssuerMetadataJsonParser.parseMetaData(json, issuer, policy)
    }
}

private fun CredentialIssuerId.wellKnown() = URLBuilder(Url(value.value.toURI()))
    .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
    .build()
    .toURI()
    .toURL()
