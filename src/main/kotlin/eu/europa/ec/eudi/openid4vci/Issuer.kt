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
         * @param credentialIssuerId The id of the credential issuer
         * @param policy policy for signed metadata
         *
         * @return the issuer's [CredentialIssuerMetadata] and list
         *  of [CIAuthorizationServerMetadata][OAUTH2 server(s) metadata] used by the issuer
         */
        suspend fun metaData(
            httpClient: HttpClient,
            credentialIssuerId: CredentialIssuerId,
            policy: IssuerMetadataPolicy,
        ): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> = coroutineScope {
            with(httpClient) {
                val issuerMetadata = run {
                    val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
                    resolver.resolve(credentialIssuerId, policy).getOrThrow()
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
         * @param httpClient an http client, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         * @param requestEncryptionSpecFactory a factory method to generate the issuance request encryption
         *
         * @return if wallet's [config] can satisfy the requirements of [credentialOffer] an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        fun make(
            config: OpenId4VCIConfig,
            credentialOffer: CredentialOffer,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
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
                            httpClient,
                        )
                    }

            val tokenEndpointClient =
                TokenEndpointClient(
                    credentialOffer.credentialIssuerIdentifier,
                    credentialOffer.authorizationServerMetadata,
                    config,
                    dPoPJwtFactory,
                    httpClient,
                )

            val authorizeIssuance =
                AuthorizeIssuanceImpl(
                    credentialOffer,
                    config,
                    authorizationEndpointClient,
                    tokenEndpointClient,
                )

            val issuanceEncryptionSpecs = issuanceEncryptionSpecs(
                encryptionSupportConfig = config.encryptionSupportConfig,
                credentialRequestEncryption = credentialOffer.credentialIssuerMetadata.credentialRequestEncryption,
                credentialResponseEncryption = credentialOffer.credentialIssuerMetadata.credentialResponseEncryption,
                requestEncryptionSpecFactory = requestEncryptionSpecFactory,
                responseEncryptionSpecFactory = responseEncryptionSpecFactory,
            ).getOrThrow()

            val requestIssuance = run {
                val credentialEndpointClient =
                    CredentialEndpointClient(
                        credentialOffer.credentialIssuerMetadata.credentialEndpoint,
                        dPoPJwtFactory,
                        httpClient,
                    )
                val nonceEndpointClient = credentialOffer.credentialIssuerMetadata.nonceEndpoint?.let {
                    NonceEndpointClient(
                        credentialOffer.credentialIssuerMetadata.nonceEndpoint,
                        httpClient,
                    )
                }
                RequestIssuanceImpl(
                    credentialOffer,
                    config,
                    credentialEndpointClient,
                    nonceEndpointClient,
                    credentialOffer.credentialIssuerMetadata.batchCredentialIssuance,
                    issuanceEncryptionSpecs,
                )
            }

            val queryForDeferredCredential =
                when (val deferredEndpoint = credentialOffer.credentialIssuerMetadata.deferredCredentialEndpoint) {
                    null -> QueryForDeferredCredential.NotSupported
                    else -> {
                        val refreshAccessToken = RefreshAccessToken(config.clock, tokenEndpointClient)
                        val deferredEndPointClient =
                            DeferredEndPointClient(deferredEndpoint, dPoPJwtFactory, httpClient)
                        QueryForDeferredCredential(refreshAccessToken, deferredEndPointClient, issuanceEncryptionSpecs)
                    }
                }

            val notifyIssuer =
                when (val notificationEndpoint = credentialOffer.credentialIssuerMetadata.notificationEndpoint) {
                    null -> NotifyIssuer.NoOp
                    else -> {
                        val notificationEndPointClient =
                            NotificationEndPointClient(notificationEndpoint, dPoPJwtFactory, httpClient)
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
                    val authorizationServerMetadata = credentialOffer.authorizationServerMetadata

                    val tokenEndpoint =
                        checkNotNull(authorizationServerMetadata.tokenEndpointURI?.toURL()) {
                            "Missing token endpoint"
                        }

                    return DeferredIssuanceContext(
                        DeferredIssuerConfig(
                            credentialIssuerId = credentialOffer.credentialIssuerIdentifier,
                            client = config.client,
                            authServerId = URI(authorizationServerMetadata.issuer.value).toURL(),
                            tokenEndpoint = tokenEndpoint,
                            dPoPSigner = dPoPJwtFactory?.signer,
                            clientAttestationPoPBuilder = config.clientAttestationPoPBuilder,
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
         * @param httpClient an http client, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of the resolved credentialOffer an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun make(
            config: OpenId4VCIConfig,
            credentialOfferUri: String,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
        ): Result<Issuer> = runCatching {
            val credentialOfferRequestResolver = CredentialOfferRequestResolver(httpClient, config.issuerMetadataPolicy)
            val credentialOffer = credentialOfferRequestResolver.resolve(credentialOfferUri).getOrThrow()
            make(config, credentialOffer, httpClient, requestEncryptionSpecFactory, responseEncryptionSpecFactory).getOrThrow()
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
         * @param httpClient an http client, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of credential issuer, an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun makeWalletInitiated(
            config: OpenId4VCIConfig,
            credentialIssuerId: CredentialIssuerId,
            credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
        ): Result<Issuer> = runCatching {
            require(credentialConfigurationIdentifiers.isNotEmpty()) {
                "At least one credential configuration identifier must be specified"
            }

            val (credentialIssuerMetadata, authServersMetadata) =
                metaData(httpClient, credentialIssuerId, config.issuerMetadataPolicy)

            val credentialOffer =
                CredentialOffer(
                    credentialIssuerId,
                    credentialIssuerMetadata,
                    authServersMetadata.first(),
                    credentialConfigurationIdentifiers,
                    Grants.AuthorizationCode(issuerState = null),
                )

            make(config, credentialOffer, httpClient, requestEncryptionSpecFactory, responseEncryptionSpecFactory).getOrThrow()
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
