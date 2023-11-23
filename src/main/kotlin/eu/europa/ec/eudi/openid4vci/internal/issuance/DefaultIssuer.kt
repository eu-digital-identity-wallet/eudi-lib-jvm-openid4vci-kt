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
import kotlinx.coroutines.CoroutineDispatcher
import java.util.*

/**
 * Default implementation of [Issuer] interface
 *  @param issuerMetadata  The credential issuer's metadata.
 *  @param ktorHttpClientFactory Factory method to generate ktor http clients
 *  @param responseEncryptionSpecFactory   Provider method to generate the expected issuer's encrypted response,
 *  if issuer enforces encrypted responses. A default implementation is provided to callers that internally
 *
 */
internal class DefaultIssuer(
    authorizationServerMetadata: CIAuthorizationServerMetadata,
    private val issuerMetadata: CredentialIssuerMetadata,
    config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
    coroutineDispatcher: CoroutineDispatcher,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
) : Issuer {

    private val authorizer: IssuanceAuthorizer =
        IssuanceAuthorizer(coroutineDispatcher, authorizationServerMetadata, config, ktorHttpClientFactory)
    private val issuanceRequester: IssuanceRequester =
        IssuanceRequester(coroutineDispatcher, issuerMetadata, ktorHttpClientFactory)

    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec? by lazy {
        val responseEncryptionSpec = when (val encryption = issuerMetadata.credentialResponseEncryption) {
            CredentialResponseEncryption.NotRequired -> null
            is CredentialResponseEncryption.Required -> responseEncryptionSpecFactory(encryption)
        }

        val issuerEncryption = issuerMetadata.credentialResponseEncryption
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
        responseEncryptionSpec
    }

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialMetadata>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> = runCatching {
        val scopes = credentials.filterIsInstance<CredentialMetadata.ByScope>().map { it.scope }.toMutableList()
        val state = UUID.randomUUID().toString()
        val (codeVerifier, getAuthorizationCodeUrl) =
            authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()

        UnauthorizedRequest.ParRequested(getAuthorizationCodeUrl, codeVerifier)
    }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved =
        UnauthorizedRequest.AuthorizationCodeRetrieved(authorizationCode, pkceVerifier)

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
        runCatching {
            val (accessToken, nonce) =
                authorizer.requestAccessTokenAuthFlow(authorizationCode.code, pkceVerifier.codeVerifier).getOrThrow()
            nonce
                ?.let { AuthorizedRequest.ProofRequired(AccessToken(accessToken), nonce) }
                ?: AuthorizedRequest.NoProofRequired(AccessToken(accessToken))
        }

    override suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialMetadata>,
        preAuthorizationCode: PreAuthorizationCode,
    ): Result<AuthorizedRequest> = runCatching {
        val (accessToken, nonce) =
            authorizer.requestAccessTokenPreAuthFlow(
                preAuthorizationCode.preAuthorizedCode,
                preAuthorizationCode.pin,
            ).getOrThrow()

        nonce
            ?.let { AuthorizedRequest.ProofRequired(AccessToken(accessToken), nonce) }
            ?: AuthorizedRequest.NoProofRequired(AccessToken(accessToken))
    }

    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            credentialMetadata
                .matchIssuerSupportedCredential()
                .constructIssuanceRequest(claimSet, null)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialMetadata: CredentialMetadata,
        claimSet: ClaimSet?,
        bindingKey: BindingKey,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            with(credentialMetadata.matchIssuerSupportedCredential()) {
                constructIssuanceRequest(
                    claimSet,
                    bindingKey.createProofWithKey(this, cNonce.value),
                )
            }
        }
    }

    /**
     * Validate that the provided evidence is one of those that issuer supports
     */
    private fun BindingKey.createProofWithKey(credentialSpec: CredentialSupported, cNonce: String): Proof =
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
                    aud(issuerMetadata.credentialIssuerIdentifier.toString())
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
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { (meta, claimSet) ->
                    meta.matchIssuerSupportedCredential().constructIssuanceRequest(claimSet, null)
                },
            )
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialMetadata, ClaimSet?, BindingKey>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            val credentialRequests = credentialsMetadata.map { (meta, claimSet, bindingKey) ->
                with(meta.matchIssuerSupportedCredential()) {
                    constructIssuanceRequest(
                        claimSet,
                        bindingKey.createProofWithKey(this, cNonce.value),
                    )
                }
            }
            CredentialIssuanceRequest.BatchCredentials(credentialRequests)
        }
    }

    private fun CredentialMetadata.matchIssuerSupportedCredential(): CredentialSupported = when (this) {
        is CredentialMetadata.ByScope ->
            supportedCredentialByScope(this)

        is CredentialMetadata.ByFormat ->
            Formats.matchSupportedCredentialByType(this, issuerMetadata)
    }

    private fun supportedCredentialByScope(
        scoped: CredentialMetadata.ByScope,
    ): CredentialSupported =
        issuerMetadata.credentialsSupported
            .firstOrNull { it.scope == scoped.scope.value }
            ?: error("Issuer does not support issuance of credential scope: ${scoped.scope}")

    private fun CredentialSupported.constructIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): CredentialIssuanceRequest.SingleCredential {
        fun assertSupported(p: Proof) {
            val proofType = when (p) {
                is Proof.Jwt -> ProofType.JWT
                is Proof.Cwt -> ProofType.CWT
            }
            require(proofTypesSupported.contains(proofType)) {
                "Provided proof type $proofType is not one of supported [${this.proofTypesSupported}]."
            }
        }
        proof?.let { assertSupported(it) }
        return Formats.constructIssuanceRequest(this, claimSet, proof, responseEncryptionSpec).getOrThrow()
    }

    override suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired = AuthorizedRequest.ProofRequired(accessToken, cNonce)

    override suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<DeferredCredentialQueryOutcome> =
        issuanceRequester.placeDeferredCredentialRequest(accessToken, deferredCredential.transactionId)

    private suspend fun requestIssuance(
        token: AccessToken,
        issuanceRequestSupplier: () -> CredentialIssuanceRequest,
    ): SubmittedRequest = when (val credentialRequest = issuanceRequestSupplier()) {
        is CredentialIssuanceRequest.SingleCredential -> {
            issuanceRequester.placeIssuanceRequest(token, credentialRequest).fold(
                onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                onFailure = { handleIssuanceFailure(it) },
            )
        }

        is CredentialIssuanceRequest.BatchCredentials -> {
            issuanceRequester.placeBatchIssuanceRequest(token, credentialRequest).fold(
                onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                onFailure = { handleIssuanceFailure(it) },
            )
        }
    }

    private fun handleIssuanceFailure(error: Throwable): SubmittedRequest.Errored = when (error) {
        is CredentialIssuanceError.InvalidProof ->
            SubmittedRequest.InvalidProof(CNonce(error.cNonce, error.cNonceExpiresIn))

        is CredentialIssuanceError ->
            SubmittedRequest.Failed(error)

        else -> throw error
    }
}
