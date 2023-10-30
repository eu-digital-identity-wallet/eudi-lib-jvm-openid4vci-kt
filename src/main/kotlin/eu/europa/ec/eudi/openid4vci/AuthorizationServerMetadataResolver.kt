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

import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultAuthorizationServerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.ktor.KtorAuthorizationServerMetadataResolver
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Indicates an error during the resolution of an Authorization Server's metadata.
 */
class AuthorizationServerMetadataResolutionException(reason: Throwable) : Exception(reason)

/**
 * Service for resolving the metadata of an Authorization Server.
 */
internal fun interface AuthorizationServerMetadataResolver {

    /**
     * Resolves the metadata of an [issuer].
     */
    suspend fun resolve(issuer: HttpsUrl): Result<CIAuthorizationServerMetadata>

    companion object {

        /**
         * Creates a new [AuthorizationServerMetadataResolver] instance.
         */
        operator fun invoke(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpGet: HttpGet<String>,
        ): AuthorizationServerMetadataResolver = DefaultAuthorizationServerMetadataResolver(ioCoroutineDispatcher, httpGet)

        fun ktor(
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
        ): AuthorizationServerMetadataResolver =
            KtorAuthorizationServerMetadataResolver(
                coroutineDispatcher = coroutineDispatcher,
            )
    }
}
