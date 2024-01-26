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

import eu.europa.ec.eudi.openid4vci.internal.DefaultAuthorizationServerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialIssuerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.DefaultOfferBasedIssuer
import eu.europa.ec.eudi.openid4vci.internal.KeyGenerator
import io.ktor.client.*

interface OfferBasedIssuer : AuthorizeOfferIssuance, RequestIssuance, QueryForDeferredCredential {

    companion object {

        suspend fun metaData(
            httpClient: HttpClient,
            credentialIssuerId: CredentialIssuerId,
        ): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> =
            with(httpClient) {
                val issuerMetadata = run {
                    val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
                    resolver.resolve(credentialIssuerId).getOrThrow()
                }
                val authorizationServersMetadata = issuerMetadata.authorizationServers.distinct().map { authServerUrl ->
                    val resolver = DefaultAuthorizationServerMetadataResolver(httpClient)
                    resolver.resolve(authServerUrl).getOrThrow()
                }
                issuerMetadata to authorizationServersMetadata
            }

        fun make(
            config: OpenId4VCIConfig,
            credentialOffer: CredentialOffer,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): OfferBasedIssuer {
            return DefaultOfferBasedIssuer(
                credentialOffer,
                config,
                ktorHttpClientFactory,
                responseEncryptionSpecFactory,
            )
        }

        val DefaultResponseEncryptionSpecFactory: ResponseEncryptionSpecFactory = { requiredEncryption, keyGenerationConfig ->
            val method = requiredEncryption.encryptionMethodsSupported[0]
            requiredEncryption.algorithmsSupported.firstNotNullOfOrNull { alg ->
                KeyGenerator.genKeyIfSupported(keyGenerationConfig, alg)?.let { jwk ->
                    IssuanceResponseEncryptionSpec(jwk, alg, method)
                }
            } ?: error("Could not create encryption spec")
        }
    }
}
