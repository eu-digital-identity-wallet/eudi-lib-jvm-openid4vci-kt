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
import eu.europa.ec.eudi.openid4vci.internal.ProofBuilder
import eu.europa.ec.eudi.openid4vci.internal.formats.*
import java.util.*

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
            )
        }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved =
        UnauthorizedRequest.AuthorizationCodeRetrieved(
            authorizationCode = authorizationCode,
            pkceVerifier = this.pkceVerifier,
        )

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenAuthFlow(
                    this.authorizationCode.code,
                    this.pkceVerifier.codeVerifier,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    accessToken = AccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                accessToken = AccessToken(accessToken),
            )
        }

    override suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialMetadata>,
        preAuthorizationCode: PreAuthorizationCode,
    ): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenPreAuthFlow(
                    preAuthorizationCode.preAuthorizedCode,
                    preAuthorizationCode.pin,
                ).getOrThrow()

            nonce?.let {
                AuthorizedRequest.ProofRequired(
                    accessToken = AccessToken(accessToken),
                    cNonce = nonce,
                )
            } ?: AuthorizedRequest.NoProofRequired(
                accessToken = AccessToken(accessToken),
            )
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        responseEncryptionSpecProvider: (issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            credentialMetadata
                .matchIssuerSupportedCredential()
                .constructIssuanceRequest(claimSet, null, responseEncryptionSpecProvider)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,
        responseEncryptionSpecProvider: (issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            with(credentialMetadata.matchIssuerSupportedCredential()) {
                constructIssuanceRequest(
                    claimSet,
                    bindingKey.createProofWithKey(this, cNonce.value),
                    responseEncryptionSpecProvider,
                )
            }
        }
    }

    private fun BindingKey.createProofWithKey(credentialSpec: CredentialSupported, cNonce: String): Proof =
        // Validate that the provided evidence is one of those that issuer supports
        when (this) {
            is BindingKey.Jwk -> {
                fun isAlgorithmSupported(): Boolean =
                    credentialSpec.cryptographicSuitesSupported.contains(algorithm.name)

                fun isBindingMethodSupported(): Boolean =
                    credentialSpec.cryptographicBindingMethodsSupported.contains(CryptographicBindingMethod.JWK)

                fun isProofTypeSupported(): Boolean =
                    credentialSpec.proofTypesSupported.contains(ProofType.JWT)

                if (!isAlgorithmSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.CryptographicSuiteNotSupported
                }
                if (!isBindingMethodSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.CryptographicBindingMethodNotSupported
                }
                if (!isProofTypeSupported()) {
                    throw CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
                }

                ProofBuilder.ofType(ProofType.JWT) {
                    aud(issuanceRequester.issuerMetadata.credentialIssuerIdentifier.toString())
                    jwk(this@createProofWithKey.jwk)
                    alg(this@createProofWithKey.algorithm)
                    nonce(cNonce)

                    build()
                }
            }

            is BindingKey.Did -> TODO("DID proof evidence not supported yet")
            is BindingKey.X509 -> TODO("X509 proof evidence not supported yet")
        }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialMetadata, ClaimSet?>>,
        responseEncryptionSpecProvider: (issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { pair ->
                    pair.first
                        .matchIssuerSupportedCredential()
                        .constructIssuanceRequest(pair.second, null, responseEncryptionSpecProvider)
                },
            )
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, BindingKey>>,
        responseEncryptionSpecProvider: (issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { triple ->
                    with(triple.first.matchIssuerSupportedCredential()) {
                        constructIssuanceRequest(
                            triple.second,
                            triple.third.createProofWithKey(this, cNonce.value),
                            responseEncryptionSpecProvider,
                        )
                    }
                },
            )
        }
    }

    private fun CredentialMetadata.matchIssuerSupportedCredential(): CredentialSupported =
        when (this) {
            is CredentialMetadata.ByScope -> supportedCredentialByScope(this, issuanceRequester.issuerMetadata)
            is CredentialMetadata.ByFormat ->
                Formats.matchSupportedCredentialByType(this, issuanceRequester.issuerMetadata)
        }

    private fun supportedCredentialByScope(
        scoped: CredentialMetadata.ByScope,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported =
        issuerMetadata.credentialsSupported
            .firstOrNull { it.scope == scoped.scope.value }
            ?: throw IllegalArgumentException("Issuer does not support issuance of credential scope: ${scoped.scope}")

    private fun CredentialSupported.constructIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpecProvider: (issuerResponseEncryptionMetadata: CredentialResponseEncryption) -> IssuanceResponseEncryptionSpec?,
    ): CredentialIssuanceRequest.SingleCredential {
        proof?.let {
            val proofType = when (it) {
                is Proof.Jwt -> ProofType.JWT
                is Proof.Cwt -> ProofType.CWT
            }
            require(this.proofTypesSupported.contains(proofType)) {
                "Provided proof type $proofType is not one of supported [${this.proofTypesSupported}]."
            }
        }

        val issuerEncryption = issuanceRequester.issuerMetadata.credentialResponseEncryption
        val responseEncryptionSpec =
            responseEncryptionSpecProvider(issuanceRequester.issuerMetadata.credentialResponseEncryption)

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

        return Formats.constructIssuanceRequest(this, claimSet, proof, responseEncryptionSpec).getOrThrow()
    }

    override suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired =
        AuthorizedRequest.ProofRequired(
            accessToken = accessToken,
            cNonce = cNonce,
        )

    override suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<DeferredCredentialQueryOutcome> =
        issuanceRequester.placeDeferredCredentialRequest(
            accessToken = accessToken,
            transactionId = deferredCredential.transactionId,
        )

    private suspend fun requestIssuance(
        token: AccessToken,
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
