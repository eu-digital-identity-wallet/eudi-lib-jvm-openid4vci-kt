/*
 * Copyright (c) 2023-2026 European Commission
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

import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.CredentialIssuerEndpoint
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.runCatchingCancellable
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CNonceResponse(
    @SerialName("c_nonce") val cNonce: String,
)

internal data class CNonceAndDPoPNonce(val cnonce: Nonce, val dpopNonce: Nonce?)

internal class NonceEndpointClient(
    private val nonceEndpoint: CredentialIssuerEndpoint,
    private val httpClient: HttpClient,
) {

    suspend fun getNonce(): Result<CNonceAndDPoPNonce> =
        runCatchingCancellable {
            requestNonce()
        }

    private suspend fun requestNonce(): CNonceAndDPoPNonce {
        val url = nonceEndpoint.value
        val response = httpClient.post(url)
        return if (response.status.isSuccess()) {
            val cNonceResponse = response.body<CNonceResponse>()
            CNonceAndDPoPNonce(Nonce(cNonceResponse.cNonce), response.dpopNonce())
        } else {
            throw CredentialIssuanceError.CNonceRequestFailed("Nonce request failed")
        }
    }
}
