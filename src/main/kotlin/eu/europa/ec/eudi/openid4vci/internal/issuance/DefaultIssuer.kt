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

private val NOT_YET_IMPLEMENTED: Nothing = TODO("Not Yet Implemented")

/**
 * Default implementation of [Issuer] interface
 */
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
                getAuthorizationCodeURL = getAuthorizationCodeUrl,
                pkceVerifier = codeVerifier,
                state = state,
            )
        }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: IssuanceAuthorization.AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved =
        UnauthorizedRequest.AuthorizationCodeRetrieved(
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
        preAuthorizationCode: IssuanceAuthorization.PreAuthorizationCode,
    ): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenPreAuthFlow(
                    preAuthorizationCode.preAuthorizedCode,
                    preAuthorizationCode.pin,
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
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            credentialMetadata
                .toIssuerSupportedCredential()
                .toIssuanceRequestMsoMdoc(claimSet, null, responseEncryptionSpec)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            with(credentialMetadata.toIssuerSupportedCredential()) {
                toIssuanceRequestMsoMdoc(
                    claimSet,
                    bindingKey.toSupportedProof(this, cNonce.value),
                    responseEncryptionSpec,
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
                    throw CredentialIssuanceError.ProofGenerationError.CryptographicBindingMethodNotSupported
                }
                if (!isProofTypeSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
                }

                ProofBuilder.ofType(ProofType.JWT) {
                    iss("") // ?? Get from config??
                    aud(issuanceRequester.issuerMetadata.credentialIssuerIdentifier.toString())
                    jwk(this@toSupportedProof.jwk)
                    alg(this@toSupportedProof.algorithm)
                    nonce(cNonce)

                    build()
                }
            }

            is BindingKey.Did -> TODO("DID proof evidence not supported yet")
            is BindingKey.X509 -> TODO("X509 proof evidence not supported yet")
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { pair ->
                    pair.first
                        .toIssuerSupportedCredential()
                        .toIssuanceRequestMsoMdoc(pair.second, null, responseEncryptionSpec)
                },
            )
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, BindingKey>>,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(token) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { triple ->
                    with(triple.first.toIssuerSupportedCredential()) {
                        toIssuanceRequestMsoMdoc(
                            triple.second,
                            triple.third.toSupportedProof(this, cNonce.value),
                            responseEncryptionSpec,
                        )
                    }
                },
            )
        }
    }

    private fun CredentialMetadata.toIssuerSupportedCredential(): CredentialSupported =
        when (this) {
            is CredentialMetadata.ByScope -> issuanceRequester.issuerMetadata.supportedCredentialByScope(this)
            is CredentialMetadata.ByFormat -> issuanceRequester.issuerMetadata.supportedCredentialByFormat(this)
        }

    private fun CredentialIssuerMetadata.supportedCredentialByScope(scoped: CredentialMetadata.ByScope): CredentialSupported =
        credentialsSupported
            .firstOrNull { it.scope == scoped.scope.value }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential scope: ${scoped.scope}")

    private fun CredentialIssuerMetadata.supportedCredentialByFormat(
        metadata: CredentialMetadata.ByFormat,
    ): CredentialSupported {
        return when (metadata) {
            is MsoMdocFormat.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is MsoMdocFormat.CredentialSupported && it.docType == metadata.docType
                }

            is W3CJsonLdDataIntegrityFormat.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CJsonLdDataIntegrityFormat.CredentialSupported &&
                        it.credentialDefinition.context == metadata.credentialDefinition.content &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is W3CJsonLdSignedJwtFormat.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CJsonLdSignedJwtFormat.CredentialSupported &&
                        it.credentialDefinition.context == metadata.credentialDefinition.content &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is W3CSignedJwtFormat.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is W3CSignedJwtFormat.CredentialSupported &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }

            is SdJwtVcFormat.CredentialMetadata ->
                credentialsSupported.firstOrNull {
                    it is SdJwtVcFormat.CredentialSupported &&
                        it.credentialDefinition.type == metadata.credentialDefinition.type
                }
        }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential : $metadata")
    }

    private fun CredentialSupported.toIssuanceRequestMsoMdoc(
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): CredentialIssuanceRequest.SingleCredential {
        proof?.let {
            require(this.proofTypesSupported.contains(it.type)) {
                "Provided proof type ${proof.type} is not one of supported [${this.proofTypesSupported}]."
            }
        }
        val issuerEncryption = issuanceRequester.issuerMetadata.credentialResponseEncryption
        responseEncryptionSpec?.let {
            when (issuerEncryption) {
                is CredentialResponseEncryption.NotRequired ->
                    throw CredentialIssuanceError.ResponseEncryptionError.IssuerDoesNotSupportEncryptedResponses

                is CredentialResponseEncryption.Required -> {
                    if (!issuerEncryption.algorithmsSupported.contains(it.algorithm)) {
                        throw CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
                    }
                    if (!issuerEncryption.encryptionMethodsSupported.contains(it.encryptionMethod)) {
                        throw CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
                    }
                }
            }
        }
        if (issuerEncryption is CredentialResponseEncryption.Required && responseEncryptionSpec == null) {
            throw CredentialIssuanceError.ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
        }

        return when (this) {
            is MsoMdocFormat.CredentialSupported -> toIssuanceRequestMsoMdoc(claimSet, proof, responseEncryptionSpec)
                .getOrThrow()

            is SdJwtVcFormat.CredentialSupported -> toIssuanceRequestSdJwtVc(claimSet, proof, responseEncryptionSpec)
                .getOrThrow()

            is W3CSignedJwtFormat.CredentialSupported -> NOT_YET_IMPLEMENTED

            is W3CJsonLdDataIntegrityFormat.CredentialSupported -> NOT_YET_IMPLEMENTED

            is W3CJsonLdSignedJwtFormat.CredentialSupported -> NOT_YET_IMPLEMENTED
        }
    }

    private fun MsoMdocFormat.CredentialSupported.toIssuanceRequestMsoMdoc(
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<CredentialIssuanceRequest.SingleCredential> = runCatching {
        fun validateClaimSet(claimSet: MsoMdocFormat.ClaimSet): MsoMdocFormat.ClaimSet {
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
                is MsoMdocFormat.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        MsoMdocFormat.CredentialIssuanceRequest(
            doctype = docType,
            credentialEncryptionJwk = responseEncryptionSpec?.jwk,
            credentialResponseEncryptionAlg = responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod = responseEncryptionSpec?.encryptionMethod,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
    }

    private fun SdJwtVcFormat.CredentialSupported.toIssuanceRequestSdJwtVc(
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryption?,
    ): Result<CredentialIssuanceRequest.SingleCredential> = runCatching {
        fun validateClaimSet(claimSet: SdJwtVcFormat.ClaimSet): SdJwtVcFormat.ClaimSet {
            if ((credentialDefinition.claims == null || credentialDefinition.claims.isEmpty()) && claimSet.claims.isNotEmpty()) {
                throw CredentialIssuanceError.InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [${SdJwtVcFormat.FORMAT}-${this.credentialDefinition.type}]",
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
                is SdJwtVcFormat.ClaimSet -> validateClaimSet(claimSet)
                else -> throw CredentialIssuanceError.InvalidIssuanceRequest("Invalid Claim Set provided for issuance")
            }
        }

        SdJwtVcFormat.CredentialIssuanceRequest(
            type = credentialDefinition.type,
            credentialEncryptionJwk = responseEncryptionSpec?.jwk,
            credentialResponseEncryptionAlg = responseEncryptionSpec?.algorithm,
            credentialResponseEncryptionMethod = responseEncryptionSpec?.encryptionMethod,
            proof = proof,
            claimSet = validClaimSet,
        ).getOrThrow()
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
