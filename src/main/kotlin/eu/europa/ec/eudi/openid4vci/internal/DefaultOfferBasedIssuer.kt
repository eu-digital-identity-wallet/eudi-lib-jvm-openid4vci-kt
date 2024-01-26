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
    private val credentialOffer: CredentialOffer,
    private val authorizeIssuanceImpl: AuthorizeOfferIssuanceImpl,
    private val requestIssuanceImpl: RequestIssuanceImpl,
    private val queryForDeferredCredentialImpl: QueryForDeferredCredentialImpl,
) : OfferBasedIssuer,
    QueryForDeferredCredential by queryForDeferredCredentialImpl,
    AuthorizeOfferIssuance by authorizeIssuanceImpl {

        override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
            credentialId: CredentialIdentifier,
            claimSet: ClaimSet?,
        ): Result<SubmittedRequest> {
            require(credentialOffer.credentials.contains(credentialId)) {
                "The requested credential is not authorized for issuance"
            }
            return with(requestIssuanceImpl) {
                this@requestSingle.requestSingle(credentialId, claimSet)
            }
        }

        override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
            credentialId: CredentialIdentifier,
            claimSet: ClaimSet?,
            proofSigner: ProofSigner,
        ): Result<SubmittedRequest> {
            require(credentialOffer.credentials.contains(credentialId)) {
                "The requested credential is not authorized for issuance"
            }
            return with(requestIssuanceImpl) {
                this@requestSingle.requestSingle(credentialId, claimSet, proofSigner)
            }
        }

        override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
            credentialsMetadata: List<Pair<CredentialIdentifier, ClaimSet?>>,
        ): Result<SubmittedRequest> {
            require(credentialOffer.credentials.containsAll(credentialsMetadata.map { (identifier, _) -> identifier })) {
                "One or more of the requested credentials are not authorized for issuance"
            }
            return with(requestIssuanceImpl) {
                this@requestBatch.requestBatch(credentialsMetadata)
            }
        }

        override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
            credentialsMetadata: List<Triple<CredentialIdentifier, ClaimSet?, ProofSigner>>,
        ): Result<SubmittedRequest> {
            require(credentialOffer.credentials.containsAll(credentialsMetadata.map { (identifier, _) -> identifier })) {
                "One or more of the requested credentials are not authorized for issuance"
            }
            return with(requestIssuanceImpl) {
                this@requestBatch.requestBatch(credentialsMetadata)
            }
        }

        override suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(cNonce: CNonce): AuthorizedRequest.ProofRequired =
            with(requestIssuanceImpl) {
                this@handleInvalidProof.handleInvalidProof(cNonce)
            }

        companion object {
            operator fun invoke(
                credentialOffer: CredentialOffer,
                config: OpenId4VCIConfig,
                ktorHttpClientFactory: KtorHttpClientFactory,
                responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
            ): DefaultOfferBasedIssuer =
                DefaultOfferBasedIssuer(
                    credentialOffer = credentialOffer,
                    authorizeIssuanceImpl = AuthorizeOfferIssuanceImpl(
                        credentialOffer = credentialOffer,
                        config = config,
                        ktorHttpClientFactory = ktorHttpClientFactory,
                    ),
                    requestIssuanceImpl = RequestIssuanceImpl(
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
