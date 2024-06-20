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

import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.IssuerDoesNotSupportDeferredIssuance
import eu.europa.ec.eudi.openid4vci.internal.RefreshAccessToken
import eu.europa.ec.eudi.openid4vci.internal.http.DeferredEndPointClient

sealed interface DeferredCredentialQueryOutcome : java.io.Serializable {

    data class Issued(
        val credential: IssuedCredential.Issued,
    ) : DeferredCredentialQueryOutcome

    data class IssuancePending(
        val interval: Long? = null,
    ) : DeferredCredentialQueryOutcome

    data class Errored(
        val error: String,
        val errorDescription: String? = null,
    ) : DeferredCredentialQueryOutcome
}

/**
 * An interface for querying credential issuer deferred endpoint.
 */
fun interface QueryForDeferredCredential {

    /**
     * Given an authorized request submits a deferred credential request for an identifier of a Deferred Issuance transaction.
     *
     * @param deferredCredential The identifier of a Deferred Issuance transaction.
     * @return The result of the query and a possibly refreshed [AuthorizedRequest]
     */
    suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<AuthorizedRequestAnd<DeferredCredentialQueryOutcome>>

    companion object {
        /**
         * An implementation that fails
         * To be used in case credential issuer doesn't advertise a deferred endpoint
         */
        val NotSupported: QueryForDeferredCredential =
            QueryForDeferredCredential { Result.failure(IssuerDoesNotSupportDeferredIssuance()) }

        /**
         * Factory method that produces a [QueryForDeferredCredential]
         * that is capable of refreshing the access_token if needed, and if possible.
         *
         * @param refreshAccessToken the ability to refresh the [AuthorizedRequest]
         * @param deferredEndPointClient client of the deferred endpoint
         * @param responseEncryptionSpec the credential response encryption specification
         * that has been sent to the credential issuer
         */
        internal operator fun invoke(
            refreshAccessToken: RefreshAccessToken,
            deferredEndPointClient: DeferredEndPointClient,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): QueryForDeferredCredential = object : QueryForDeferredCredential {

            override suspend fun AuthorizedRequest.queryForDeferredCredential(
                deferredCredential: IssuedCredential.Deferred,
            ): Result<AuthorizedRequestAnd<DeferredCredentialQueryOutcome>> = runCatching {
                val refreshed = refreshIfNeeded(this)
                val outcome = placeDeferredCredentialRequest(refreshed, deferredCredential)
                refreshed to outcome
            }

            private suspend fun refreshIfNeeded(authorizedRequest: AuthorizedRequest): AuthorizedRequest =
                with(refreshAccessToken) {
                    authorizedRequest.refreshIfNeeded().getOrThrow()
                }

            private suspend fun placeDeferredCredentialRequest(
                authorizedRequest: AuthorizedRequest,
                deferredCredential: IssuedCredential.Deferred,
            ): DeferredCredentialQueryOutcome =
                deferredEndPointClient.placeDeferredCredentialRequest(
                    authorizedRequest.accessToken,
                    deferredCredential,
                    responseEncryptionSpec,
                ).getOrThrow()
        }
    }
}
