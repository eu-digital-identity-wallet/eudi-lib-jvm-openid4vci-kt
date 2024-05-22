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
import eu.europa.ec.eudi.openid4vci.AuthorizationServerMetadataResolutionException
import eu.europa.ec.eudi.openid4vci.AuthorizationServerMetadataResolver
import eu.europa.ec.eudi.openid4vci.CIAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import net.minidev.json.JSONObject

internal class DefaultAuthorizationServerMetadataResolver(
    private val httpClient: HttpClient,
) : AuthorizationServerMetadataResolver {
    override suspend fun resolve(authServerUrl: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        fetchOidcServerMetadata(authServerUrl)
            .recoverCatching { fetchOauthServerMetadata(authServerUrl).getOrThrow() }
            .mapCatching { it.apply { expectIssuer(authServerUrl) } }
            .mapError(::AuthorizationServerMetadataResolutionException)

    /**
     * Tries to fetch the [CIAuthorizationServerMetadata] for the provided [OpenID Connect Authorization Server][issuer].
     * The well-known location __/.well-known/openid-configuration__ is used.
     */
    private suspend fun fetchOidcServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            val url = issuer.metadataUrl("/.well-known/openid-configuration")
            fetchAndParse(url, OIDCProviderMetadata::parse)
        }.recoverCatching {
            val url = issuer.metadataUrl("/.well-known/openid-configuration", false)
            fetchAndParse(url, OIDCProviderMetadata::parse)
        }

    /**
     * Tries to fetch the [CIAuthorizationServerMetadata] for the provided [OAuth2 Authorization Server][issuer].
     * The well-known location __/.well-known/oauth-authorization-server__ is used.
     */
    private suspend fun fetchOauthServerMetadata(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            val url = issuer.metadataUrl("/.well-known/oauth-authorization-server")
            fetchAndParse(url, AuthorizationServerMetadata::parse)
        }.recoverCatching {
            val url = issuer.metadataUrl("/.well-known/oauth-authorization-server", false)
            fetchAndParse(url, AuthorizationServerMetadata::parse)
        }

    /**
     * Fetches the content of the provided [url], parses it as a [JSONObject], and further parses it
     * using the provided [parser].
     */
    private suspend fun <T> fetchAndParse(url: Url, parser: (String) -> T): T {
        val body = httpClient.get(url).body<String>()
        return parser(body)
    }
}

/**
 * Verifies the issuer of this [CIAuthorizationServerMetadata] equals the [expected] one.
 */
private fun CIAuthorizationServerMetadata.expectIssuer(expected: HttpsUrl) =
    require(issuer == Issuer(expected.value.toURI())) { "issuer does not match the expected value" }

/**
 * Gets a well-known metadata URL of an issuer.
 *
 * @receiver the Issuer
 * @param metadata the well-known metadata URL to get
 * @param specCompliant whether to get a spec-compliant URL or not
 */
private fun HttpsUrl.metadataUrl(metadata: String, specCompliant: Boolean = true): Url =
    with(Url(this.value.toString())) {
        return if (specCompliant) {
            URLBuilder(this).apply {
                path("/${metadata.removePrefix("/").removeSuffix("/")}${pathSegments.joinToString("/")}")
            }.build()
        } else {
            URLBuilder(this)
                .appendPathSegments("/${metadata.removePrefix("/").removeSuffix("/")}", encodeSlash = false)
                .build()
        }
    }
