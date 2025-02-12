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

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import eu.europa.ec.eudi.openid4vci.internal.*
import eu.europa.ec.eudi.openid4vci.internal.http.*
import io.ktor.client.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.net.URI

/**
 * Entry point to the issuance library
 *
 * Provides the following capabilities
 * - [AuthorizeIssuance]
 * - [RequestIssuance]
 * - [QueryForDeferredCredential]
 * - [NotifyIssuer]
 *
 * [Issuer] lifecycle is bound to serve a single [Issuer.credentialOffer]
 *
 * Typically, one of the factory methods found on the companion object can be used to get an instance of [Issuer].
 *
 */
interface Issuer :
    AuthorizeIssuance,
    RequestIssuance,
    QueryForDeferredCredential,
    NotifyIssuer {

    val credentialOffer: CredentialOffer
    val dPoPJwtFactory: DPoPJwtFactory?

    /**
     * A convenient method for obtaining a [DeferredIssuanceContext], in case of a deferred issuance
     * that wallet wants to query again at a later time, using [DeferredIssuer].
     *
     * Typically, wallet should store this [DeferredIssuanceContext] and [use it][DeferredIssuer] at a later time
     *
     * @receiver the state of issuance
     * @param deferredCredential the transaction id returned by the issuer
     * @return the context that would be necessary to instantiate a [DeferredIssuer]
     */
    fun AuthorizedRequest.deferredContext(deferredCredential: SubmissionOutcome.Deferred): DeferredIssuanceContext

    companion object {

        /**
         * Fetches & validates the issuer's [CredentialIssuerMetadata] and list
         * of [CIAuthorizationServerMetadata][OAUTH2 server(s) metadata] used by the issuer
         *
         * @param httpClient The client to fetch the metadata
         * @param credentialIssuerId The id of the credential issuer.
         *
         * @return the issuer's [CredentialIssuerMetadata] and list
         *  of [CIAuthorizationServerMetadata][OAUTH2 server(s) metadata] used by the issuer
         */
        suspend fun metaData(
            httpClient: HttpClient,
            credentialIssuerId: CredentialIssuerId,
        ): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> = coroutineScope {
            with(httpClient) {
                val issuerMetadata = run {
                    val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
                    resolver.resolve(credentialIssuerId).getOrThrow()
                }
                val authorizationServersMetadata =
                    issuerMetadata.authorizationServers.distinct().map { authServerUrl ->
                        async {
                            val resolver = DefaultAuthorizationServerMetadataResolver(httpClient)
                            resolver.resolve(authServerUrl).getOrThrow()
                        }
                    }.awaitAll()

                issuerMetadata to authorizationServersMetadata
            }
        }

        /**
         * Factory method for creating an instance of [Issuer] based on a resolved and validated credential offer.
         *
         * @param config wallet's configuration options
         * @param credentialOffer the offer for which the issuer is being created
         * @param ktorHttpClientFactory a factory for obtaining http clients, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of [credentialOffer] an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        fun make(
            config: OpenId4VCIConfig,
            credentialOffer: CredentialOffer,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): Result<Issuer> = runCatching {
            config.client.ensureSupportedByAuthorizationServer(credentialOffer.authorizationServerMetadata)

            val dPoPJwtFactory = config.dPoPSigner?.let { signer ->
                DPoPJwtFactory.createForServer(
                    signer = signer,
                    clock = config.clock,
                    oauthServerMetadata = credentialOffer.authorizationServerMetadata,
                ).getOrThrow()
            }

            val authorizationEndpointClient =
                credentialOffer.authorizationServerMetadata
                    .authorizationEndpointURI
                    ?.let {
                        AuthorizationEndpointClient(
                            credentialOffer.credentialIssuerIdentifier,
                            credentialOffer.authorizationServerMetadata,
                            config,
                            dPoPJwtFactory,
                            ktorHttpClientFactory,
                        )
                    }

            val tokenEndpointClient =
                TokenEndpointClient(
                    credentialOffer.credentialIssuerIdentifier,
                    credentialOffer.authorizationServerMetadata,
                    config,
                    dPoPJwtFactory,
                    ktorHttpClientFactory,
                )

            val authorizeIssuance =
                AuthorizeIssuanceImpl(
                    credentialOffer,
                    config,
                    authorizationEndpointClient,
                    tokenEndpointClient,
                )

            val responseEncryptionSpec =
                responseEncryptionSpec(credentialOffer, config, responseEncryptionSpecFactory).getOrThrow()

            val requestIssuance = run {
                val credentialEndpointClient =
                    CredentialEndpointClient(
                        credentialOffer.credentialIssuerMetadata.credentialEndpoint,
                        dPoPJwtFactory,
                        ktorHttpClientFactory,
                    )
                RequestIssuanceImpl(
                    credentialOffer,
                    config,
                    credentialEndpointClient,
                    credentialOffer.credentialIssuerMetadata.batchCredentialIssuance,
                    responseEncryptionSpec,
                )
            }

            val queryForDeferredCredential =
                when (val deferredEndpoint = credentialOffer.credentialIssuerMetadata.deferredCredentialEndpoint) {
                    null -> QueryForDeferredCredential.NotSupported
                    else -> {
                        val refreshAccessToken = RefreshAccessToken(config.clock, tokenEndpointClient)
                        val deferredEndPointClient =
                            DeferredEndPointClient(deferredEndpoint, dPoPJwtFactory, ktorHttpClientFactory)
                        QueryForDeferredCredential(refreshAccessToken, deferredEndPointClient, responseEncryptionSpec)
                    }
                }

            val notifyIssuer =
                when (val notificationEndpoint = credentialOffer.credentialIssuerMetadata.notificationEndpoint) {
                    null -> NotifyIssuer.NoOp
                    else -> {
                        val notificationEndPointClient =
                            NotificationEndPointClient(notificationEndpoint, dPoPJwtFactory, ktorHttpClientFactory)
                        NotifyIssuer(notificationEndPointClient)
                    }
                }

            object :
                Issuer,
                AuthorizeIssuance by authorizeIssuance,
                RequestIssuance by requestIssuance,
                QueryForDeferredCredential by queryForDeferredCredential,
                NotifyIssuer by notifyIssuer {
                override val credentialOffer: CredentialOffer
                    get() = credentialOffer

                override val dPoPJwtFactory: DPoPJwtFactory?
                    get() = dPoPJwtFactory

                override fun AuthorizedRequest.deferredContext(
                    deferredCredential: SubmissionOutcome.Deferred,
                ): DeferredIssuanceContext {
                    val credentialIssuerMetadata = credentialOffer.credentialIssuerMetadata
                    val authorizationServerMetadata = credentialOffer.authorizationServerMetadata

                    val deferredEndpoint =
                        checkNotNull(credentialIssuerMetadata.deferredCredentialEndpoint?.value) {
                            "Missing deferred credential endpoint"
                        }

                    val tokenEndpoint =
                        checkNotNull(authorizationServerMetadata.tokenEndpointURI?.toURL()) {
                            "Missing token endpoint"
                        }

                    return DeferredIssuanceContext(
                        DeferredIssuerConfig(
                            credentialIssuerId = credentialOffer.credentialIssuerIdentifier,
                            client = config.client,
                            deferredEndpoint = deferredEndpoint,
                            authServerId = URI(authorizationServerMetadata.issuer.value).toURL(),
                            tokenEndpoint = tokenEndpoint,
                            dPoPSigner = dPoPJwtFactory?.signer,
                            clientAttestationPoPBuilder = config.clientAttestationPoPBuilder,
                            responseEncryptionSpec = responseEncryptionSpec,
                            clock = config.clock,
                        ),
                        AuthorizedTransaction(this@deferredContext, deferredCredential.transactionId),
                    )
                }
            }
        }

        /**
         * Factory method for creating an instance of [Issuer] based on a credential offer URI.
         * Method will try to first resolve the [credentialOfferUri] into a [CredentialOffer]
         * proceed with the creation of the [Issuer]
         *
         * @param config wallet's configuration options
         * @param credentialOfferUri the credential offer uri to be resolved
         * @param ktorHttpClientFactory a factory for obtaining http clients, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of the resolved credentialOffer an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun make(
            config: OpenId4VCIConfig,
            credentialOfferUri: String,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): Result<Issuer> = runCatching {
            val credentialOfferRequestResolver = CredentialOfferRequestResolver(ktorHttpClientFactory)
            val credentialOffer = credentialOfferRequestResolver.resolve(credentialOfferUri).getOrThrow()
            make(config, credentialOffer, ktorHttpClientFactory, responseEncryptionSpecFactory).getOrThrow()
        }

        /**
         * Factory method for creating an instance of [Issuer] with a credential offer (Wallet initiated)
         * This requires out-of-band knowledge of [issuer][credentialIssuerId] and one or more
         * [credentialConfigurationIdentifiers].
         *
         * This is equivalent to instantiating a credential offer, using authorization code grant,
         * without `issuer_state`.
         *
         * @param config wallet's configuration options
         * @param credentialIssuerId the id of the credential issuer
         * @param credentialConfigurationIdentifiers a list of credential configuration identifiers
         * @param ktorHttpClientFactory a factory for obtaining http clients, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of credential issuer, an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun makeWalletInitiated(
            config: OpenId4VCIConfig,
            credentialIssuerId: CredentialIssuerId,
            credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): Result<Issuer> = runCatching {
            require(credentialConfigurationIdentifiers.isNotEmpty()) {
                "At least one credential configuration identifier must be specified"
            }

            val (credentialIssuerMetadata, authServersMetadata) =
                ktorHttpClientFactory().use { httpClient -> metaData(httpClient, credentialIssuerId) }

            val credentialOffer =
                CredentialOffer(
                    credentialIssuerId,
                    credentialIssuerMetadata,
                    authServersMetadata.first(),
                    credentialConfigurationIdentifiers,
                    Grants.AuthorizationCode(issuerState = null),
                )

            make(config, credentialOffer, ktorHttpClientFactory, responseEncryptionSpecFactory).getOrThrow()
        }

        val DefaultResponseEncryptionSpecFactory: ResponseEncryptionSpecFactory =
            { supportedAlgorithmsAndMethods, keyGenerationConfig ->
                val method = supportedAlgorithmsAndMethods.encryptionMethods[0]
                supportedAlgorithmsAndMethods.algorithms.firstNotNullOfOrNull { alg ->
                    KeyGenerator.genKeyIfSupported(keyGenerationConfig, alg)?.let { jwk ->
                        IssuanceResponseEncryptionSpec(jwk, alg, method)
                    }
                }
            }
    }
}

private const val ATTEST_JWT_CLIENT_AUTH = "attest_jwt_client_auth"

internal fun Client.ensureSupportedByAuthorizationServer(authorizationServerMetadata: CIAuthorizationServerMetadata) {
    val tokenEndPointAuthMethods =
        authorizationServerMetadata.tokenEndpointAuthMethods.orEmpty()

    when (this) {
        is Client.Attested -> {
            val expectedMethod = ClientAuthenticationMethod(ATTEST_JWT_CLIENT_AUTH)
            require(expectedMethod in tokenEndPointAuthMethods) {
                "$ATTEST_JWT_CLIENT_AUTH not supported by authorization server"
            }
        }

        else -> Unit
    }
}
