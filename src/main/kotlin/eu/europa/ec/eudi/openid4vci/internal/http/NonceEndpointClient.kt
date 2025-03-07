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

import eu.europa.ec.eudi.openid4vci.CNonce
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.CredentialIssuerEndpoint
import eu.europa.ec.eudi.openid4vci.KtorHttpClientFactory
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CNonceResponse(
    @SerialName("c_nonce") val cNonce: String,
)

internal class NonceEndpointClient(
    private val nonceEndpoint: CredentialIssuerEndpoint,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    suspend fun getNonce(): Result<CNonce> =
        runCatching {
            requestNonce()
        }

    private suspend fun requestNonce(): CNonce =
        ktorHttpClientFactory().use { client ->
            val url = nonceEndpoint.value
            val response = client.post(url)

            if (response.status.isSuccess()) {
                val cNonceResponse = response.body<CNonceResponse>()
                CNonce(cNonceResponse.cNonce)
            } else {
                throw CredentialIssuanceError.CNonceRequestFailed("Nonce request failed")
            }
        }
}
