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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.internal.DefaultAuthorizationServerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialIssuerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.DefaultIssuer
import eu.europa.ec.eudi.openid4vci.internal.KeyGenerator
import io.ktor.client.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

interface Issuer : AuthorizeIssuance, RequestIssuance, QueryForDeferredCredential, NotifyIssuer {

    companion object {

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

        fun make(
            config: OpenId4VCIConfig,
            credentialOffer: CredentialOffer,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): Issuer {
            return DefaultIssuer(
                credentialOffer,
                config,
                ktorHttpClientFactory,
                responseEncryptionSpecFactory,
            )
        }

        val DefaultResponseEncryptionSpecFactory: ResponseEncryptionSpecFactory =
            { responseEncryption, keyGenerationConfig ->
                when (responseEncryption) {
                    is CredentialResponseEncryption.SupportedNotRequired -> {
                        spec(responseEncryption.encryptionMethodsSupported, responseEncryption.algorithmsSupported, keyGenerationConfig)
                    }

                    is CredentialResponseEncryption.Required -> {
                        spec(responseEncryption.encryptionMethodsSupported, responseEncryption.algorithmsSupported, keyGenerationConfig)
                            ?: error("Could not create responseEncryption spec")
                    }
                    CredentialResponseEncryption.NotSupported -> null
                }
            }

        private fun spec(
            encryptionMethodsSupported: List<EncryptionMethod>,
            algorithmsSupported: List<JWEAlgorithm>,
            keyGenerationConfig: KeyGenerationConfig,
        ): IssuanceResponseEncryptionSpec? {
            val method = encryptionMethodsSupported[0]
            return algorithmsSupported.firstNotNullOfOrNull { alg ->
                KeyGenerator.genKeyIfSupported(keyGenerationConfig, alg)?.let { jwk ->
                    IssuanceResponseEncryptionSpec(jwk, alg, method)
                }
            }
        }
    }
}
