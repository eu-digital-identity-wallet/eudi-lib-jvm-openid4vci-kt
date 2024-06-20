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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.internal.DPoPJwtFactory
import eu.europa.ec.eudi.openid4vci.internal.RefreshAccessToken
import eu.europa.ec.eudi.openid4vci.internal.http.DeferredEndPointClient
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointClient
import java.io.Serializable
import java.net.URI
import java.net.URL
import java.time.Clock

data class IssuanceStoredContext(
    val clientId: ClientId,
    val deferredEndpoint: CredentialIssuerEndpoint,
    val tokenEndpoint: URL,
    val dPoPSigner: PopSigner.Jwt? = null,
    val authorizationServerSupportedDPoPAlgorithms: List<JWSAlgorithm> = emptyList(),
    val responseEncryptionSpec: IssuanceResponseEncryptionSpec? = null,
) : Serializable

data class AuthorizedTransaction(
    val authorizedRequest: AuthorizedRequest,
    val transactionId: TransactionId,
) : Serializable

interface DeferredIssuer : QueryForDeferredCredential {

    companion object {

        fun make(
            clock: Clock = Clock.systemDefaultZone(),
            storedContext: IssuanceStoredContext,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<DeferredIssuer> = runCatching {
            val dPoPJwtFactory = storedContext.dPoPSigner?.let { signer ->
                DPoPJwtFactory.create(
                    signer = signer,
                    clock = clock,
                    supportedDPopAlgorithms = storedContext.authorizationServerSupportedDPoPAlgorithms,
                ).getOrThrow()
            }

            val tokenEndpointClient = TokenEndpointClient(
                clock,
                storedContext.clientId,
                URI.create("https://willNotBeUsed"),
                storedContext.tokenEndpoint,
                dPoPJwtFactory,
                ktorHttpClientFactory,
            )

            val refreshAccessToken = RefreshAccessToken(clock, tokenEndpointClient)
            val queryForDeferredCredential = run {
                val client = DeferredEndPointClient(
                    storedContext.deferredEndpoint,
                    dPoPJwtFactory,
                    ktorHttpClientFactory,
                )
                QueryForDeferredCredential(refreshAccessToken, client, storedContext.responseEncryptionSpec)
            }

            object :
                DeferredIssuer,
                QueryForDeferredCredential by queryForDeferredCredential {}
        }
    }
}
