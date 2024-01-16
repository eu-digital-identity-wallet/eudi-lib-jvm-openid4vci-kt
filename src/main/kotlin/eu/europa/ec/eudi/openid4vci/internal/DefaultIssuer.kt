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

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest

/**
 * Default implementation of [Issuer] interface
 *  @param issuerMetadata  The credential issuer's metadata.
 *  @param ktorHttpClientFactory Factory method to generate ktor http clients
 *  @param responseEncryptionSpecFactory   Factory method to generate the expected issuer's encrypted response, if issuer enforces encrypted responses.
 *     A default implementation is provided to callers.
 */
internal class DefaultIssuer(
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
    private val issuerMetadata: CredentialIssuerMetadata,
    config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
) : Issuer {

    private val authorizer: IssuanceAuthorizer =
        IssuanceAuthorizer(authorizationServerMetadata, config, ktorHttpClientFactory)
    private val issuanceRequester: IssuanceRequester =
        IssuanceRequester(issuerMetadata, ktorHttpClientFactory)

    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec? by lazy {
        fun IssuanceResponseEncryptionSpec.validate(meta: CredentialResponseEncryption.Required) {
            ensure(algorithm in meta.algorithmsSupported) {
                ResponseEncryptionAlgorithmNotSupportedByIssuer
            }
            ensure(encryptionMethod in meta.encryptionMethodsSupported) {
                ResponseEncryptionMethodNotSupportedByIssuer
            }
        }
        when (val encryption = issuerMetadata.credentialResponseEncryption) {
            is CredentialResponseEncryption.NotRequired -> null
            is CredentialResponseEncryption.Required ->
                responseEncryptionSpecFactory(encryption, config.keyGenerationConfig).apply {
                    validate(encryption)
                }
        }
    }

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialIdentifier>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> = runCatching {
        val (codeVerifier, getAuthorizationCodeUrl) = run {
            val scopes = credentials.mapNotNull { credentialId ->
                credentialSupportedById(credentialId).scope?.let { Scope(it) }
            }
            val state = State().value
            authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()
        }

        UnauthorizedRequest.ParRequested(getAuthorizationCodeUrl, codeVerifier)
    }

    override suspend fun UnauthorizedRequest.ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): UnauthorizedRequest.AuthorizationCodeRetrieved =
        UnauthorizedRequest.AuthorizationCodeRetrieved(authorizationCode, pkceVerifier)

    override suspend fun UnauthorizedRequest.AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
        authorizer.requestAccessTokenAuthFlow(authorizationCode.code, pkceVerifier.codeVerifier)
            .map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }

    override suspend fun authorizeWithPreAuthorizationCode(
        credentials: List<CredentialIdentifier>,
        preAuthorizationCode: PreAuthorizationCode,
    ): Result<AuthorizedRequest> =
        authorizer.requestAccessTokenPreAuthFlow(
            preAuthorizationCode.preAuthorizedCode,
            preAuthorizationCode.pin,
        ).map { (accessToken, cNonce) -> AuthorizedRequest(accessToken, cNonce) }

    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            singleRequest(credentialId, claimSet)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        proofSigner: ProofSigner,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            singleRequestWithProof(credentialId, claimSet, proofSigner, cNonce)
        }
    }

    private fun singleRequestWithProof(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        proofSigner: ProofSigner,
        cNonce: CNonce,
    ): CredentialIssuanceRequest.SingleRequest {
        val credentialSupported = credentialSupportedById(credentialId)
        val proof = ProofBuilder.ofType(ProofType.JWT) {
            aud(issuerMetadata.credentialIssuerIdentifier.toString())
            publicKey(proofSigner.getBindingKey())
            credentialSpec(credentialSupported)
            nonce(cNonce.value)
            build(proofSigner)
        }
        return credentialSupported.constructIssuanceRequest(claimSet, proof)
    }

    private fun singleRequest(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
    ): CredentialIssuanceRequest.SingleRequest {
        val credentialSupported = credentialSupportedById(credentialId)
        return credentialSupported.constructIssuanceRequest(claimSet, proof = null)
    }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialIdentifier, ClaimSet?>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            CredentialIssuanceRequest.BatchRequest(
                credentialsMetadata.map { (credentialId, claimSet) ->
                    singleRequest(credentialId, claimSet)
                },
            )
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialIdentifier, ClaimSet?, ProofSigner>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            val credentialRequests = credentialsMetadata.map { (credentialId, claimSet, proofSigner) ->
                singleRequestWithProof(credentialId, claimSet, proofSigner, cNonce)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests)
        }
    }

    private fun credentialSupportedById(credentialId: CredentialIdentifier): CredentialSupported {
        val credentialSupported = issuerMetadata.credentialsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private fun CredentialSupported.constructIssuanceRequest(
        claimSet: ClaimSet?,
        proof: Proof?,
    ): CredentialIssuanceRequest.SingleRequest {
        fun assertSupported(p: Proof) {
            val proofType = when (p) {
                is Proof.Jwt -> ProofType.JWT
                is Proof.Cwt -> ProofType.CWT
            }
            require(proofType in proofTypesSupported) {
                "Provided proof type $proofType is not one of supported [$proofTypesSupported]."
            }
        }
        proof?.let { assertSupported(it) }
        return CredentialIssuanceRequest.singleRequest(this, claimSet, proof, responseEncryptionSpec)
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
    ): SubmittedRequest {
        fun handleIssuanceFailure(error: Throwable): SubmittedRequest.Errored =
            submitRequestFromError(error) ?: throw error
        return when (val credentialRequest = issuanceRequestSupplier()) {
            is CredentialIssuanceRequest.SingleRequest -> {
                issuanceRequester.placeIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }

            is CredentialIssuanceRequest.BatchRequest -> {
                issuanceRequester.placeBatchIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }
        }
    }
}

private fun submitRequestFromError(error: Throwable): SubmittedRequest.Errored? = when (error) {
    is CredentialIssuanceError.InvalidProof ->
        SubmittedRequest.InvalidProof(CNonce(error.cNonce, error.cNonceExpiresIn))
    is CredentialIssuanceError -> SubmittedRequest.Failed(error)
    else -> null
}
