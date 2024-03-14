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

internal class DefaultIssuer private constructor(
    private val authorizeIssuanceImpl: AuthorizeIssuanceImpl,
    private val requestIssuanceImpl: RequestIssuanceImpl,
    private val queryForDeferredCredentialImpl: QueryForDeferredCredentialImpl,
    private val notifyIssuerImpl: NotifyIssuerImpl,
) : Issuer,
    AuthorizeIssuance by authorizeIssuanceImpl,
    RequestIssuance by requestIssuanceImpl,
    QueryForDeferredCredential by queryForDeferredCredentialImpl,
    NotifyIssuer by notifyIssuerImpl {

        companion object {
            operator fun invoke(
                credentialOffer: CredentialOffer,
                config: OpenId4VCIConfig,
                ktorHttpClientFactory: KtorHttpClientFactory,
                responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
                preference: AuthorizeIssuancePreference = AuthorizeIssuancePreference.USE_SCOPES_FALLBACK_TO_AUTHORIZATION_DETAIL_BY_CFG_ID,
            ): DefaultIssuer = DefaultIssuer(
                authorizeIssuanceImpl = AuthorizeIssuanceImpl(
                    credentialOffer = credentialOffer,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                    preference = preference,
                ),
                requestIssuanceImpl = RequestIssuanceImpl(
                    credentialOffer = credentialOffer,
                    issuerMetadata = credentialOffer.credentialIssuerMetadata,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                    responseEncryptionSpecFactory = responseEncryptionSpecFactory,
                ),
                queryForDeferredCredentialImpl = QueryForDeferredCredentialImpl(
                    issuerMetadata = credentialOffer.credentialIssuerMetadata,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
                notifyIssuerImpl = NotifyIssuerImpl(
                    issuerMetadata = credentialOffer.credentialIssuerMetadata,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
            )
        }
    }
