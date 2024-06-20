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

import eu.europa.ec.eudi.openid4vci.AccessToken
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.NotificationFailed
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceEvent
import eu.europa.ec.eudi.openid4vci.CredentialIssuerEndpoint
import eu.europa.ec.eudi.openid4vci.KtorHttpClientFactory
import eu.europa.ec.eudi.openid4vci.internal.DPoPJwtFactory
import eu.europa.ec.eudi.openid4vci.internal.Htm
import eu.europa.ec.eudi.openid4vci.internal.bearerOrDPoPAuth
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

internal class NotificationEndPointClient(
    private val notificationEndpoint: CredentialIssuerEndpoint,
    private val dPoPJwtFactory: DPoPJwtFactory?,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {

    suspend fun notifyIssuer(
        accessToken: AccessToken,
        event: CredentialIssuanceEvent,
    ): Result<Unit> = runCatching {
        ktorHttpClientFactory().use { client ->
            val url = notificationEndpoint.value.value
            val response = client.post(url) {
                bearerOrDPoPAuth(dPoPJwtFactory, url, Htm.POST, accessToken)
                contentType(ContentType.Application.Json)
                setBody(NotificationTO.from(event))
            }
            if (response.status.isSuccess()) {
                Unit
            } else {
                val errorResponse = response.body<GenericErrorResponseTO>()
                throw NotificationFailed(errorResponse.error)
            }
        }
    }
}
