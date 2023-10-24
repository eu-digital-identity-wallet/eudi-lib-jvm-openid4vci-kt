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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import eu.europa.ec.eudi.openid4vci.*
import java.util.*

internal class DefaultIssuer(
    val authorizer: IssuanceAuthorizer,
    val issuanceRequester: IssuanceRequester,
) : Issuer {

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialMetadata>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> =
        runCatching {
            val scopes = credentials.filterIsInstance<CredentialMetadata.ByScope>().map { it.scope }
            val state = UUID.randomUUID().toString()
            val (codeVerifier, getAuthorizationCodeUrl) =
                authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()

            // Transition state
            UnauthorizedRequest.ParRequested(
                credentials = credentials,
                getAuthorizationCodeURL = getAuthorizationCodeUrl,
                pkceVerifier = codeVerifier,
                state = state,
            )
        }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: IssuanceAuthorization.AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved =
        UnauthorizedRequest.AuthorizationCodeRetrieved(
            credentials = credentials,
            authorizationCode = authorizationCode,
            pkceVerifier = this.pkceVerifier,
        )

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenAuthFlow(
                    this.authorizationCode.authorizationCode,
                    this.pkceVerifier.codeVerifier,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    token = IssuanceAccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialMetadata>,
        authorizationCode: IssuanceAuthorization.PreAuthorizationCode,
    ): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenPreAuthFlow(
                    authorizationCode.preAuthorizedCode,
                    authorizationCode.pin,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    token = IssuanceAccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest> =
        runCatching {
            requestIssuance(token) {
                credentialMetadata
                    .toIssuerSupportedCredential()
                    .toIssuanceRequest(claimSet, null)
            }
        }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        proof: Proof,
    ): Result<SubmittedRequest> =
        runCatching {
            requestIssuance(token) {
                credentialMetadata
                    .toIssuerSupportedCredential()
                    .toIssuanceRequest(claimSet, proof)
            }
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
    ): Result<SubmittedRequest> =
        runCatching {
            // TODO: Check if issuer exposes batch endpoint
            requestIssuance(token) {
                CredentialIssuanceRequest.BatchCredentials(
                    credentialRequests = credentialsMetadata.map { pair ->
                        pair.first
                            .toIssuerSupportedCredential()
                            .toIssuanceRequest(pair.second, null)
                    },
                )
            }
        }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, Proof>>,
    ): Result<SubmittedRequest> =
        runCatching {
            // TODO: Check if issuer exposes batch endpoint
            requestIssuance(token) {
                CredentialIssuanceRequest.BatchCredentials(
                    credentialRequests = credentialsMetadata.map { triple ->
                        triple.first
                            .toIssuerSupportedCredential()
                            .toIssuanceRequest(triple.second, triple.third)
                    },
                )
            }
        }

    private fun CredentialMetadata.toIssuerSupportedCredential(): CredentialSupported =
        when (this) {
            is CredentialMetadata.ByScope -> issuanceRequester.issuerMetadata.supportedCredentialByScope(this)
            is CredentialMetadata.ByProfile -> issuanceRequester.issuerMetadata.supportedCredentialByProfile(this)
        }

    private fun CredentialIssuerMetadata.supportedCredentialByScope(scoped: CredentialMetadata.ByScope): CredentialSupported =
        credentialsSupported
            .firstOrNull { it.scope == scoped.scope.value }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential scope: ${scoped.scope}")

    private fun CredentialIssuerMetadata.supportedCredentialByProfile(
        metadata: CredentialMetadata.ByProfile,
    ): CredentialSupported {
        return when (metadata) {
            is CredentialMetadata.MsoMdoc ->
                credentialsSupported.firstOrNull {
                    it is CredentialSupported.MsoMdoc && it.docType == metadata.docType
                }

            is CredentialMetadata.JsonLdDataIntegrity ->
                credentialsSupported.firstOrNull {
                    it is CredentialSupported.JsonLdDataIntegrity
                }

            is CredentialMetadata.JsonLdSignedJwt ->
                credentialsSupported.firstOrNull {
                    it is CredentialSupported.JsonLdSignedJwt
                }

            is CredentialMetadata.SignedJwt ->
                credentialsSupported.firstOrNull {
                    it is CredentialSupported.SignedJwt
                }
        }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential : $metadata")
    }

    private fun CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): CredentialIssuanceRequest.SingleCredential {
        proof?.let {
            require(this.proofTypesSupported.contains(it.type())) {
                "Provided proof type ${proof.type()} is not one of supported [${this.proofTypesSupported}]."
            }
        }
        // TODO: Validate crypto alg and method
        return when (this) {
            is CredentialSupported.MsoMdoc -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is CredentialSupported.SignedJwt -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is CredentialSupported.JsonLdDataIntegrity -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is CredentialSupported.JsonLdSignedJwt -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
        }
    }

    private fun CredentialSupported.MsoMdoc.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> = runCatching {
        fun validateClaimSet(claimSet: ClaimSet.MsoMdoc): ClaimSet.MsoMdoc {
            if (claims.isEmpty() && claimSet.claims.isNotEmpty()) {
                CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${this.docType}]").raise()
            }
            claimSet.claims.entries.forEach { requestedClaim ->
                this@toIssuanceRequest.claims.get(requestedClaim.key)?.let { supportedClaim ->
                    if (!supportedClaim.keys.containsAll(requestedClaim.value.keys)) {
                        CredentialIssuanceError.InvalidIssuanceRequest(
                            "Claim names requested are not supported by issuer",
                        ).raise()
                    }
                }
                ?: CredentialIssuanceError.InvalidIssuanceRequest("Namespace ${requestedClaim.key} not supported by issuer").raise()
            }
            return claimSet
        }
        val validClaimSet =
            claimSet?.let {
                when (claimSet) {
                    is ClaimSet.MsoMdoc -> validateClaimSet(claimSet)
                    else -> CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance").raise()
                }
            }

        CredentialIssuanceRequest.SingleCredential.MsoMdocIssuanceRequest(
            doctype = docType,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    private fun CredentialSupported.SignedJwt.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    private fun CredentialSupported.JsonLdDataIntegrity.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    private fun CredentialSupported.JsonLdSignedJwt.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    override suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired =
        AuthorizedRequest.ProofRequired(
            token = token,
            cNonce = cNonce,
        )

    private suspend fun requestIssuance(
        token: IssuanceAccessToken,
        issuanceRequestSupplier: () -> CredentialIssuanceRequest,
    ): SubmittedRequest =
        when (val credentialRequest = issuanceRequestSupplier()) {
            is CredentialIssuanceRequest.SingleCredential -> {
                issuanceRequester.placeIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            SubmittedRequest.Success(it)
                        },
                        onFailure = {
                            handleIssuanceFailure(it)
                        },
                    )
            }

            is CredentialIssuanceRequest.BatchCredentials -> {
                issuanceRequester.placeBatchIssuanceRequest(token, credentialRequest)
                    .fold(
                        onSuccess = {
                            SubmittedRequest.Success(it)
                        },
                        onFailure = {
                            handleIssuanceFailure(it)
                        },
                    )
            }
        }

    private fun handleIssuanceFailure(throwable: Throwable): SubmittedRequest.Errored {
        return if (throwable is CredentialIssuanceException) {
            if (throwable.error is CredentialIssuanceError.InvalidProof) {
                SubmittedRequest.InvalidProof(
                    cNonce = CNonce(throwable.error.cNonce, throwable.error.cNonceExpiresIn),
                )
            } else {
                SubmittedRequest.Failed(throwable.error)
            }
        } else {
            throw throwable
        }
    }
}
