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

import eu.europa.ec.eudi.openid4vci.internal.http.NotificationEndPointClient

sealed interface CredentialIssuanceEvent {

    val id: NotificationId
    val description: String?

    data class Accepted(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent

    data class Failed(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent

    data class Deleted(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent
}

/**
 * A service for notifying credential issuer
 * about a [CredentialIssuanceEvent]
 */
fun interface NotifyIssuer {

    suspend fun AuthorizedRequest.notify(
        event: CredentialIssuanceEvent,
    ): Result<Unit>

    companion object {

        /**
         * No operation notifier (does nothing)
         * Used in case credential issuer doesn't advertise a notification endpoint
         */
        val NoOp: NotifyIssuer = NotifyIssuer { Result.success(Unit) }

        /**
         * Factory method for creating a [NotifyIssuer]
         *
         * @param notificationEndPointClient a client for the notification endpoint
         * @return a [NotifyIssuer]
         */
        internal operator fun invoke(notificationEndPointClient: NotificationEndPointClient): NotifyIssuer =
            NotifyIssuer { event -> notificationEndPointClient.notifyIssuer(accessToken, event) }
    }
}
