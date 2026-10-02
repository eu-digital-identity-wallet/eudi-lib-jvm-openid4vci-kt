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
    private val dPoPJwtFactory: suspend () -> DPoPJwtFactory?,
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
        val response = httpClient.request(
            HttpRequestBuilder()
                .apply {
                    method = HttpMethod.Post
                    url.takeFrom(notificationEndpoint.value)
                    bearerOrDPoPAuth(accessToken, dPoPJwtFactory(), resourceServerDpopNonce)
                    contentType(ContentType.Application.Json)
                    setBody(NotificationTO.from(event))
                },
        )

        val newResourceServerDpopNonce = response.dpopNonce()
        return if (response.status.isSuccess()) {
            newResourceServerDpopNonce ?: resourceServerDpopNonce
        } else {
            when (response.status) {
                HttpStatusCode.Unauthorized -> {
                    val wwwAuthenticate = response.headers[HttpHeaders.WWWAuthenticate]
                    if (null != wwwAuthenticate) {
                        if (isResourceServerDpopNonceRequired(wwwAuthenticate) && null != newResourceServerDpopNonce && !retried) {
                            notifyIssuerInternal(
                                accessToken,
                                newResourceServerDpopNonce,
                                event,
                                true,
                            )
                        } else {
                            val errorResponse =
                                GenericErrorResponseTO.fromWWWAuthenticate(wwwAuthenticate)
                                    ?: GenericErrorResponseTO.InvalidToken
                            throw NotificationFailed(errorResponse.error, errorResponse.errorDescription)
                        }
                    } else {
                        throw NotificationFailed("invalid_token")
                    }
                }

                else -> {
                    val errorResponse = response.body<GenericErrorResponseTO>()
                    throw NotificationFailed(errorResponse.error, errorResponse.errorDescription)
                }
            }
        }
    }
}
