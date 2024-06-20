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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.AuthorizationServerClient
import eu.europa.ec.eudi.openid4vci.internal.http.IssuanceServerClient
import java.time.Clock

internal class QueryForDeferredCredentialImpl(
    private val issuanceServerClient: IssuanceServerClient,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : QueryForDeferredCredential {

    override suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<AuthorizedRequestAnd<DeferredCredentialQueryOutcome>> = runCatching {

        val outcome = issuanceServerClient.placeDeferredCredentialRequest(
            accessToken,
            deferredCredential,
            responseEncryptionSpec
        ).getOrThrow()

        this to outcome
    }



    companion object {

        fun withRefreshableAccessToken(
            clock: Clock,
            authorizationServerClient: AuthorizationServerClient,
            issuanceServerClient: IssuanceServerClient,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): QueryForDeferredCredential {
            val refreshAccessToken = RefreshAccessToken(clock, authorizationServerClient)
            val proxy = QueryForDeferredCredentialImpl(issuanceServerClient, responseEncryptionSpec)
            return RefreshTokenIfNeededAndQueryForDeferredCredential(refreshAccessToken, proxy)
        }
    }
}

private class RefreshTokenIfNeededAndQueryForDeferredCredential(
    private val refreshAccessToken: RefreshAccessToken,
    private val proxy: QueryForDeferredCredential
) : QueryForDeferredCredential {

    override suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred
    ): Result<AuthorizedRequestAnd<DeferredCredentialQueryOutcome>> = runCatching{
        val refreshed = refreshAccessToken.refreshIfNeeded(this).getOrThrow()
        with(proxy) {
            refreshed.queryForDeferredCredential(deferredCredential).getOrThrow()
        }
    }
}
