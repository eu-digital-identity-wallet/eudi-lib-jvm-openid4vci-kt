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

import eu.europa.ec.eudi.openid4vci.internal.*
import eu.europa.ec.eudi.openid4vci.internal.RequestIssuanceImpl
import eu.europa.ec.eudi.openid4vci.internal.http.IssuanceServerClient
import io.ktor.client.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

interface Issuer : AuthorizeIssuance, RequestIssuance, QueryForDeferredCredential, NotifyIssuer {

    val credentialOffer: CredentialOffer

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
            val dPoPJwtFactory = config.dPoPSigner?.let { signer ->
                DPoPJwtFactory.createForServer(
                    signer = signer,
                    clock = config.clock,
                    oauthServerMetadata = credentialOffer.authorizationServerMetadata,
                ).getOrThrow()
            }
            val issuanceServerClient = IssuanceServerClient(
                credentialOffer.credentialIssuerMetadata,
                ktorHttpClientFactory,
                dPoPJwtFactory,
            )
            val authorizeIssuance = AuthorizeIssuanceImpl(
                credentialOffer,
                config,
                ktorHttpClientFactory,
                dPoPJwtFactory,
            )
            val responseEncryptionSpec =
                responseEncryptionSpec(credentialOffer, config, responseEncryptionSpecFactory).getOrThrow()
            val requestIssuance = RequestIssuanceImpl(
                credentialOffer,
                config,
                issuanceServerClient,
                responseEncryptionSpec,
            )
            val queryForDeferredCredential = QueryForDeferredCredentialImpl(
                issuanceServerClient,
                responseEncryptionSpec,
            )
            val notifyIssuer = NotifyIssuerImpl(issuanceServerClient)

            object :
                Issuer,
                AuthorizeIssuance by authorizeIssuance,
                RequestIssuance by requestIssuance,
                QueryForDeferredCredential by queryForDeferredCredential,
                NotifyIssuer by notifyIssuer {
                override val credentialOffer: CredentialOffer
                    get() = credentialOffer
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
