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

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.openid4vci.CIAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import net.minidev.json.JSONObject
import java.net.URL

/**
 * Indicates an error during the resolution of an Authorization Server's metadata.
 */
internal class AuthorizationServerMetadataResolutionException(reason: Throwable) : Exception(reason)

/**
 * Service for resolving the metadata of an Authorization Server.
 */
internal object AuthorizationServerMetadataResolver {

    suspend fun HttpClient.resolve(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            fetchOidcServerMetadata(issuer)
                .recoverCatching { fetchOauthServerMetadata(issuer).getOrThrow() }
                .mapCatching { it.apply { expectIssuer(issuer) } }
                .mapError(::AuthorizationServerMetadataResolutionException)
                .getOrThrow()
        }
}

/**
 * Tries to fetch the [CIAuthorizationServerMetadata] for the provided [OpenID Connect Authorization Server][issuer].
 * The well-known location __/.well-known/openid-configuration__ is used.
 */
private suspend fun HttpClient.fetchOidcServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
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
private suspend fun HttpClient.fetchOauthServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
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
private suspend fun <T> HttpClient.fetchAndParse(url: URL, parser: (String) -> T): T {
    val body = get(url).body<String>()
    return parser(body)
}

/**
 * Verifies the issuer of this [CIAuthorizationServerMetadata] equals the [expected] one.
 */
private fun CIAuthorizationServerMetadata.expectIssuer(expected: HttpsUrl) =
    require(issuer == Issuer(expected.value.toURI())) { "issuer does not match the expected value" }
