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
package eu.europa.ec.eudi.openid4vci.internal.credentialoffer

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.mapError
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext
import net.minidev.json.JSONObject
import java.net.URL

/**
 * Default implementation for [AuthorizationServerMetadataResolver].
 */
internal class DefaultAuthorizationServerMetadataResolver(
    private val coroutineDispatcher: CoroutineDispatcher,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) : AuthorizationServerMetadataResolver {

    override suspend fun resolve(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        fetchOidcServerMetadata(issuer)
            .recoverCatching { fetchOauthServerMetadata(issuer).getOrThrow() }
            .mapCatching { it.apply { expectIssuer(issuer) } }
            .mapError(::AuthorizationServerMetadataResolutionException)

    /**
     * Tries to fetch the [CIAuthorizationServerMetadata] for the provided [OpenID Connect Authorization Server][issuer].
     * The well-known location __/.well-known/openid-configuration__ is used.
     */
    private suspend fun fetchOidcServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            val url =
                URLBuilder(issuer.value.toString())
                    .appendPathSegments("/.well-known/openid-configuration", encodeSlash = false)
                    .build()
                    .toURI()
                    .toURL()

            fetchAndParse(url, OIDCProviderMetadata::parse)
        }

    /**
     * Tries to fetch the [CIAuthorizationServerMetadata] for the provided [OAuth2 Authorization Server][issuer].
     * The well known location __/.well-known/oauth-authorization-server__ is used.
     */
    private suspend fun fetchOauthServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            val url =
                URLBuilder(issuer.value.toString())
                    .appendPathSegments("/.well-known/oauth-authorization-server", encodeSlash = false)
                    .build()
                    .toURI()
                    .toURL()

            fetchAndParse(url, AuthorizationServerMetadata::parse)
        }

    /**
     * Fetches the content of the provided [url], parses it as a [JSONObject], and further parses it
     * using the provided [parser].
     */
    private suspend fun <T> fetchAndParse(url: URL, parser: (String) -> T): T =
        withContext(coroutineDispatcher + CoroutineName("$url")) {
            ktorHttpClientFactory().use { client ->
                val body = client.get(url).body<String>()
                parser(body)
            }
        }

    companion object {
    }
}

/**
 * Verifies the issuer of this [CIAuthorizationServerMetadata] equals the [expected] one.
 */
private fun CIAuthorizationServerMetadata.expectIssuer(expected: HttpsUrl) =
    require(issuer == Issuer(expected.value)) { "issuer does not match the expected value" }
