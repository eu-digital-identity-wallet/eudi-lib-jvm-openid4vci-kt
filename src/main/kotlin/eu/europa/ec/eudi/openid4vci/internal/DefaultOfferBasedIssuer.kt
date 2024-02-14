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

internal class DefaultOfferBasedIssuer private constructor(
    private val authorizeIssuanceImpl: AuthorizeOfferIssuanceImpl,
    private val requestIssuanceImpl: RequestIssuanceImpl,
    private val queryForDeferredCredentialImpl: QueryForDeferredCredentialImpl,
) : Issuer,
    AuthorizeOfferIssuance by authorizeIssuanceImpl,
    RequestIssuance by requestIssuanceImpl,
    QueryForDeferredCredential by queryForDeferredCredentialImpl {

        companion object {
            operator fun invoke(
                credentialOffer: CredentialOffer,
                config: OpenId4VCIConfig,
                ktorHttpClientFactory: KtorHttpClientFactory,
                responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
            ): DefaultOfferBasedIssuer = DefaultOfferBasedIssuer(
                authorizeIssuanceImpl = AuthorizeOfferIssuanceImpl(
                    credentialOffer = credentialOffer,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
                requestIssuanceImpl = RequestIssuanceImpl(
                    credentialOffer = credentialOffer,
                    issuerMetadata = credentialOffer.credentialIssuerMetadata,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                    responseEncryptionSpecFactory = responseEncryptionSpecFactory,
                ),
                queryForDeferredCredentialImpl = QueryForDeferredCredentialImpl(
                    credentialOffer.credentialIssuerMetadata,
                    ktorHttpClientFactory,
                ),
            )
        }
    }
