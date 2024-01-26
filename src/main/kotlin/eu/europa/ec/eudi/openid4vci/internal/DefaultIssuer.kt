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

/**
 * Default implementation of [Issuer] interface
 *  @param issuerMetadata  The credential issuer's metadata.
 *  @param authorizationServerMetadata The metadata of the OAUTH2 or OIDC server
 *  that protects the credential issuer endpoints
 *  @param config The configuration options
 *  @param ktorHttpClientFactory Factory method to generate ktor http clients
 *  @param responseEncryptionSpecFactory   Factory method to generate the expected issuer's encrypted response,
 *  if needed.
 */
internal class DefaultIssuer private constructor(
    authorizeIssuanceImpl: AuthorizeIssuanceImpl,
    requestIssuanceImpl: RequestIssuanceImpl,
    queryForDeferredCredentialImpl: QueryForDeferredCredentialImpl,
) : Issuer,
    AuthorizeIssuance by authorizeIssuanceImpl,
    RequestIssuance by requestIssuanceImpl,
    QueryForDeferredCredential by queryForDeferredCredentialImpl {

        companion object {
            operator fun invoke(
                issuerMetadata: CredentialIssuerMetadata,
                authorizationServerMetadata: CIAuthorizationServerMetadata,
                config: OpenId4VCIConfig,
                ktorHttpClientFactory: KtorHttpClientFactory,
                responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
            ): DefaultIssuer = DefaultIssuer(
                authorizeIssuanceImpl = AuthorizeIssuanceImpl(
                    issuerMetadata = issuerMetadata,
                    authorizationServerMetadata = authorizationServerMetadata,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
                requestIssuanceImpl = RequestIssuanceImpl(
                    issuerMetadata = issuerMetadata,
                    config = config,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                    responseEncryptionSpecFactory = responseEncryptionSpecFactory,
                ),
                queryForDeferredCredentialImpl = QueryForDeferredCredentialImpl(
                    issuerMetadata = issuerMetadata,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
            )
        }
    }
