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
    private val authorizer: IssuanceAuthorizer,
    private val issuanceRequester: IssuanceRequester,
) : Issuer {

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialMetadata>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> =
        runCatching {
            val scopes = credentials.filterIsInstance<CredentialMetadata.ByScope>().map { it.scope }.toMutableList()
            val state = UUID.randomUUID().toString()
            val (codeVerifier, getAuthorizationCodeUrl) =
                authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()

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
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            credentialMetadata
                .toIssuerSupportedCredential()
                .toIssuanceRequest(claimSet, null)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            with(credentialMetadata.toIssuerSupportedCredential()) {
                toIssuanceRequest(
                    claimSet,
                    bindingKey.toSupportedProof(this, cNonce.value),
                )
            }
        }
    }

    private fun BindingKey.toSupportedProof(credentialSpec: CredentialSupported, cNonce: String): Proof =
        // Validate that the provided evidence is one of those that issuer supports
        when (this) {
            is BindingKey.Jwk -> {
                fun isAlgorithmIsSupported(): Boolean =
                    credentialSpec.cryptographicSuitesSupported.contains(algorithm.name)

                fun isBindingMethodSupported(): Boolean =
                    credentialSpec.cryptographicBindingMethodsSupported.contains(CryptographicBindingMethod.JWK)

                fun isProofTypeSupported(): Boolean =
                    credentialSpec.proofTypesSupported.contains(ProofType.JWT)

                if (!isAlgorithmIsSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.BindingMethodNotSupported
                }
                if (!isBindingMethodSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.CryptographicSuiteNotSupported
                }
                if (!isProofTypeSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
                }

                Proof.Jwt(
                    with(
                        ProofBuilder.ofType(ProofType.JWT),
                    ) {
                        iss("") // TODO: Get from config??
                        aud(issuanceRequester.issuerMetadata.credentialIssuerIdentifier.toString())
                        jwk(this@toSupportedProof.jwk)
                        alg(this@toSupportedProof.algorithm)
                        nonce(cNonce)

                        build()
                    },
                )
            }

            is BindingKey.Did -> TODO("DID proof evidence not supported yet")
            is BindingKey.X509 -> TODO("X509 proof evidence not supported yet")
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
    ): Result<SubmittedRequest> = runCatching {
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
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, BindingKey>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { triple ->
                    with(triple.first.toIssuerSupportedCredential()) {
                        toIssuanceRequest(
                            triple.second,
                            triple.third.toSupportedProof(this, cNonce.value),
                        )
                    }
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
            is MsoMdocProfile.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is MsoMdocProfile.CredentialSupported && it.docType == metadata.docType
                }

            is W3CJsonLdDataIntegrityProfile.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CJsonLdDataIntegrityProfile.CredentialSupported &&
                        it.credentialDefinition.context == metadata.credentialDefinition.content &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is W3CJsonLdSignedJwtProfile.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CJsonLdSignedJwtProfile.CredentialSupported &&
                        it.credentialDefinition.context == metadata.credentialDefinition.content &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is W3CSignedJwtProfile.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CSignedJwtProfile.CredentialSupported &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is SdJwtVcProfile.CredentialMetadata -> TODO()
        }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential : $metadata")
    }

    private fun CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): CredentialIssuanceRequest.SingleCredential {
        proof?.let {
            require(this.proofTypesSupported.contains(it.type)) {
                "Provided proof type ${proof.type} is not one of supported [${this.proofTypesSupported}]."
            }
        }
        // TODO: Validate crypto alg and method
        return when (this) {
            is MsoMdocProfile.CredentialSupported -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is W3CSignedJwtProfile.CredentialSupported -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is W3CJsonLdDataIntegrityProfile.CredentialSupported -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is W3CJsonLdSignedJwtProfile.CredentialSupported -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
            is SdJwtVcProfile.CredentialSupported -> this.toIssuanceRequest(claimSet, proof).getOrThrow()
        }
    }

    private fun MsoMdocProfile.CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> = runCatching {
        fun validateClaimSet(claimSet: MsoMdocProfile.ClaimSet): MsoMdocProfile.ClaimSet {
            if (claims.isEmpty() && claimSet.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${this.docType}]",
                )
            }
            claimSet.forEach { (nameSpace, attributes) ->
                claims[nameSpace]?.let { supportedClaim ->
                    if (!supportedClaim.keys.containsAll(attributes.keys)) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest(
                            "Claim names requested are not supported by issuer",
                        )
                    }
                }
                    ?: throw CredentialIssuanceError.InvalidIssuanceRequest("Namespace $nameSpace not supported by issuer")
            }
            return claimSet
        }

        val validClaimSet = claimSet?.let {
            when (claimSet) {
                is MsoMdocProfile.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        MsoMdocProfile.CredentialIssuanceRequest(
            doctype = docType,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    private fun SdJwtVcProfile.CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> = runCatching {
        fun validateClaimSet(claimSet: SdJwtVcProfile.ClaimSet): SdJwtVcProfile.ClaimSet {
            if (credentialDefinition.claims.isNullOrEmpty() && claimSet.claims.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [${SdJwtVcProfile.FORMAT}-${this.credentialDefinition.type}]",
                )
            }
            if (credentialDefinition.claims != null && !credentialDefinition.claims.keys.containsAll(claimSet.claims.keys)) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Claim names requested are not supported by issuer",
                )
            }
            return claimSet
        }

        val validClaimSet = claimSet?.let {
            when (claimSet) {
                is SdJwtVcProfile.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        SdJwtVcProfile.CredentialIssuanceRequest(
            type = credentialDefinition.type,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    private fun W3CSignedJwtProfile.CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    private fun W3CJsonLdDataIntegrityProfile.CredentialSupported.toIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): Result<CredentialIssuanceRequest.SingleCredential> {
        TODO("Not yet implemented")
    }

    private fun W3CJsonLdSignedJwtProfile.CredentialSupported.toIssuanceRequest(
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
        return when (throwable) {
            is CredentialIssuanceError.InvalidProof -> SubmittedRequest.InvalidProof(
                cNonce = CNonce(throwable.cNonce, throwable.cNonceExpiresIn),
            )
            is CredentialIssuanceError -> SubmittedRequest.Failed(throwable)
            else -> throw throwable
        }
    }
}
