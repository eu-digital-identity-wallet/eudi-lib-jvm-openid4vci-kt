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

import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.mapError
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext

/**
 * Default implementation for [AuthorizationServerMetadataResolver].
 */
internal class DefaultAuthorizationServerMetadataResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher,
    private val httpGet: HttpGet<String>,
) : AuthorizationServerMetadataResolver {

    override suspend fun resolve(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata> =
        runCatching {
            withContext(ioCoroutineDispatcher + CoroutineName("/.well-known/openid-configuration")) {
                val url =
                    URLBuilder(issuer.value.toString())
                        .appendPathSegments("/.well-known/openid-configuration", encodeSlash = false)
                        .build()
                        .toURI()
                        .toURL()

                httpGet.get(url)
                    .mapCatching { JSONObjectUtils.parse(it) }
                    .mapCatching { OIDCProviderMetadata.parse(it) }
                    .getOrThrow()
            }.also {
                if (it.issuer != Issuer(issuer.value)) {
                    throw IllegalArgumentException("issuer does not match the expected value")
                }
            }
        }.mapError(::AuthorizationServerMetadataResolutionException)
}
