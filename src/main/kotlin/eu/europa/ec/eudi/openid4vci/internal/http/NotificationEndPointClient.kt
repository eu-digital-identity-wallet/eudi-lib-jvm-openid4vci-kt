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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.NotificationFailed
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

internal class NotificationEndPointClient(
    private val notificationEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val httpClient: HttpClient,
) {

    suspend fun notifyIssuer(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        event: CredentialIssuanceEvent,
    ): Result<Nonce?> =
        runCatchingCancellable {
            notifyIssuerInternal(accessToken, resourceServerDpopNonce, event, false)
        }

    private suspend fun notifyIssuerInternal(
        accessToken: AccessToken,
        resourceServerDpopNonce: Nonce?,
        event: CredentialIssuanceEvent,
        retried: Boolean,
    ): Nonce? {
        val url = notificationEndpoint.value
        val jwt = if (accessToken is AccessToken.DPoP && dPoPJwtFactory != null) {
            dPoPJwtFactory.createDPoPJwt(Htm.POST, url, accessToken, resourceServerDpopNonce).getOrThrow()
                .serialize()
        } else null

        val response = httpClient.post(url) {
            bearerOrDPoPAuth(accessToken, jwt)
            contentType(ContentType.Application.Json)
            setBody(NotificationTO.from(event))
        }

        return if (response.status.isSuccess()) {
            response.dpopNonce() ?: resourceServerDpopNonce
        } else {
            val newResourceServerDpopNonce = response.dpopNonce()
            if (response.isResourceServerDpopNonceRequired() && newResourceServerDpopNonce != null && !retried) {
                notifyIssuerInternal(accessToken, newResourceServerDpopNonce, event, true)
            } else {
                val errorResponse = response.body<GenericErrorResponseTO>()
                throw NotificationFailed(errorResponse.error)
            }
        }
    }
}
