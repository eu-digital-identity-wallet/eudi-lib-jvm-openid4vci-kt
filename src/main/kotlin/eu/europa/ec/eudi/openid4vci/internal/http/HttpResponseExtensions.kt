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
package eu.europa.ec.eudi.openid4vci.internal.http

import com.nimbusds.openid.connect.sdk.Nonce
import io.ktor.client.statement.*
import io.ktor.http.*

/**
 * Extracts the new Nonce value for DPoP from this [HttpResponse].
 */
internal fun HttpResponse.dpopNonce(): Nonce? = headers["DPoP-Nonce"]?.let(::Nonce)

/**
 * Checks if this [HttpResponse] is from a Resource Server that requires a Nonce value to be included in the DPoP Header.
 */
internal fun HttpResponse.isResourceServerDpopNonceRequired(): Boolean =
    when (status) {
        HttpStatusCode.Unauthorized -> {
            val wwwAuthenticate = headers[HttpHeaders.WWWAuthenticate]
            wwwAuthenticate?.let {
                it.contains("DPoP") && it.contains("error=\"use_dpop_nonce\"")
            } ?: false
        }

        else -> false
    }
