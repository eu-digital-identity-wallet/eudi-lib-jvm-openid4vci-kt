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

import eu.europa.ec.eudi.openid4vci.DeferredIssuer.Companion.make
import eu.europa.ec.eudi.openid4vci.internal.RefreshAccessToken
import eu.europa.ec.eudi.openid4vci.internal.http.DeferredEndPointClient
import eu.europa.ec.eudi.openid4vci.internal.http.TokenEndpointClient
import java.net.URI
import java.net.URL
import java.time.Clock

/**
 * A minimal configuration needed to [instantiate][DeferredIssuer.make]
 * the [DeferredIssuer].
 *
 * @param client the client for the wallet
 * @param deferredEndpoint the URL of the deferred endpoint
 * @param tokenEndpoint the URL of the token endpoint. Will be used if needed, to refresh the access token
 * @param dPoPSigner the signer that was used for DPoP. Must be provided only if DPoP was used.
 * @param responseEncryptionSpec the encryption key, used for credential response encryption. Used only
 * it was included in the initial credential request
 * @param clock Wallet's clock
 */
data class DeferredIssuerConfig(
    val credentialIssuerId: CredentialIssuerId,
    val client: Client,
    val deferredEndpoint: URL,
    val authServerId: URL,
    val tokenEndpoint: URL,
    val dPoPSigner: PopSigner.Jwt? = null,
    val clientAttestationPoPBuilder: ClientAttestationPoPBuilder = ClientAttestationPoPBuilder.Default,
    val responseEncryptionSpec: IssuanceResponseEncryptionSpec? = null,
    val clock: Clock = Clock.systemDefaultZone(),
)

/**
 * The information required to query the deferred endpoint.
 * @param authorizedRequest the state of the issuance
 * @param transactionId the id returned by deferred endpoint
 */
data class AuthorizedTransaction(
    val authorizedRequest: AuthorizedRequest.NoProofRequired,
    val transactionId: TransactionId,
) {
    constructor(authorizedRequest: AuthorizedRequest, transactionId: TransactionId) : this(
        authorizedRequest = when (authorizedRequest) {
            is AuthorizedRequest.NoProofRequired -> authorizedRequest
            is AuthorizedRequest.ProofRequired -> AuthorizedRequest.NoProofRequired(
                accessToken = authorizedRequest.accessToken,
                refreshToken = authorizedRequest.refreshToken,
                credentialIdentifiers = authorizedRequest.credentialIdentifiers,
                timestamp = authorizedRequest.timestamp,
                authorizationServerDpopNonce = authorizedRequest.authorizationServerDpopNonce,
                resourceServerDpopNonce = authorizedRequest.resourceServerDpopNonce,
            )
        },
        transactionId = transactionId,
    )
}

/**
 * Represents what a wallet needs to keep to be
 * able to query deferred endpoint on a later time.
 *
 * It can be obtained via [Issuer.deferredContext]
 */
data class DeferredIssuanceContext(
    val config: DeferredIssuerConfig,
    val authorizedTransaction: AuthorizedTransaction,
)

/**
 * A specialized issuer with the capability to [QueryForDeferredCredential]
 *
 * In contrast to the [Issuer] that already supports this functionality
 * the [DeferredIssuer] requires a [minimal set of data][DeferredIssuanceContext]
 * in ordered to be [instantiated][make].
 *
 * Typically, wallet could persist [DeferredIssuanceContext] and
 * use the [DeferredIssuer.queryForDeferredCredential] to query again the deferred endpoint.
 *
 * The [DeferredIssuanceContext] can be obtained by [Issuer.deferredContext]
 *
 * Finally, [DeferredIssuer] supports transparent refresh of access token
 */
interface DeferredIssuer : QueryForDeferredCredential {

    companion object {

        /**
         * A convenient method for querying the deferred endpoint given a [ctx].
         * Creates a [DeferredIssuer] using the [ctx] and then queries the endpoint
         *
         * @param ctx the context containing the data needed to instantiate the issuer and query the endpoint
         * @param ktorHttpClientFactory a factory for getting http clients, used while interacting with issuer
         *
         * @return The method returns a pair comprised of:
         * - On the right side, there is the [outcome][DeferredCredentialQueryOutcome] of querying the endpoint
         * - On the left side, there is a possibly updated [DeferredIssuanceContext]. It will have a value
         *   only in case the outcome was [DeferredCredentialQueryOutcome.IssuancePending]. Otherwise, it would be null.
         */
        suspend fun queryForDeferredCredential(
            ctx: DeferredIssuanceContext,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<Pair<DeferredIssuanceContext?, DeferredCredentialQueryOutcome>> = runCatching {
            val deferredIssuer = make(ctx.config, ktorHttpClientFactory).getOrThrow()
            val (newAuthorized, outcome) = with(deferredIssuer) {
                with(ctx.authorizedTransaction.authorizedRequest) {
                    val transactionId = ctx.authorizedTransaction.transactionId
                    queryForDeferredCredential(transactionId).getOrThrow()
                }
            }
            val newCtx = when (outcome) {
                is DeferredCredentialQueryOutcome.IssuancePending, is DeferredCredentialQueryOutcome.Errored -> {
                    if (newAuthorized != ctx.authorizedTransaction.authorizedRequest) {
                        check(newAuthorized is AuthorizedRequest.NoProofRequired)
                        val newAuthorizedTransaction = ctx.authorizedTransaction.copy(authorizedRequest = newAuthorized)
                        ctx.copy(authorizedTransaction = newAuthorizedTransaction)
                    } else {
                        ctx
                    }
                }

                is DeferredCredentialQueryOutcome.Issued -> null // will not be needed
            }
            newCtx to outcome
        }

        /**
         * Factory method for getting an instance of [DeferredIssuer]
         *
         * @param config the minimal configuration needed.
         * @param ktorHttpClientFactory a factory for getting http clients, used while interacting with issuer
         *
         * @return the deferred issuer instance
         */
        fun make(
            config: DeferredIssuerConfig,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<DeferredIssuer> = runCatching {
            val dPoPJwtFactory = config.dPoPSigner?.let { signer ->
                DPoPJwtFactory(signer = signer, clock = config.clock)
            }

            val tokenEndpointClient = TokenEndpointClient(
                config.credentialIssuerId,
                config.clock,
                config.client,
                URI.create("https://willNotBeUsed"), // this will not be used
                config.authServerId,
                config.tokenEndpoint,
                dPoPJwtFactory,
                config.clientAttestationPoPBuilder,
                ktorHttpClientFactory,
            )

            val refreshAccessToken = RefreshAccessToken(config.clock, tokenEndpointClient)
            val deferredEndPointClient = DeferredEndPointClient(
                CredentialIssuerEndpoint.invoke(config.deferredEndpoint.toString()).getOrThrow(),
                dPoPJwtFactory,
                ktorHttpClientFactory,
            )
            val queryForDeferredCredential =
                QueryForDeferredCredential(
                    refreshAccessToken,
                    deferredEndPointClient,
                    config.responseEncryptionSpec,
                )
            object :
                DeferredIssuer,
                QueryForDeferredCredential by queryForDeferredCredential {}
        }
    }
}
