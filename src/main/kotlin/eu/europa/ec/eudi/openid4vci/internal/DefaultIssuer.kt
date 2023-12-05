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
import eu.europa.ec.eudi.openid4vci.internal.formats.ClaimSet
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported
import eu.europa.ec.eudi.openid4vci.internal.formats.Formats
import java.util.*

/**
 * Default implementation of [Issuer] interface
 *  @param issuerMetadata  The credential issuer's metadata.
 *  @param ktorHttpClientFactory Factory method to generate ktor http clients
 *  @param responseEncryptionSpecFactory   Factory method to generate the expected issuer's encrypted response, if issuer enforces encrypted responses.
 *     A default implementation is provided to callers.
 */
internal class DefaultIssuer(
    authorizationServerMetadata: CIAuthorizationServerMetadata,
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
        fun IssuanceResponseEncryptionSpec.isValid(meta: CredentialResponseEncryption.Required) {
            if (!meta.algorithmsSupported.contains(algorithm)) {
                throw CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
            }
            if (!meta.encryptionMethodsSupported.contains(encryptionMethod)) {
                throw CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
            }
        }
        when (val encryption = issuerMetadata.credentialResponseEncryption) {
            is CredentialResponseEncryption.NotRequired -> null
            is CredentialResponseEncryption.Required -> responseEncryptionSpecFactory(encryption, config.keyGenerationConfig).also {
                it.isValid(encryption)
            }
        }
    }

    override suspend fun pushAuthorizationCodeRequest(
        credentials: List<CredentialIdentifier>,
        issuerState: String?,
    ): Result<UnauthorizedRequest.ParRequested> = runCatching {
        val scopes = credentials.map {
            it.matchIssuerSupportedCredential().scope?.let { Scope(it) }
        }.filterNotNull()

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
            credentialId
                .matchIssuerSupportedCredential()
                .constructIssuanceRequest(claimSet, null)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        proofSigner: ProofSigner,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            with(credentialId.matchIssuerSupportedCredential()) {
                constructIssuanceRequest(
                    claimSet,
                    createProof(issuerMetadata, this, cNonce.value, proofSigner, ProofType.JWT),
                )
            }
        }
    }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialIdentifier, ClaimSet?>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            CredentialIssuanceRequest.BatchCredentials(
                credentialRequests = credentialsMetadata.map { (id, claimSet) ->
                    id.matchIssuerSupportedCredential().constructIssuanceRequest(claimSet, null)
                },
            )
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialIdentifier, ClaimSet?, ProofSigner>>,
    ): Result<SubmittedRequest> = runCatching {
        requestIssuance(accessToken) {
            val credentialRequests = credentialsMetadata.map { (id, claimSet, proofSigner) ->
                with(id.matchIssuerSupportedCredential()) {
                    constructIssuanceRequest(
                        claimSet,
                        createProof(issuerMetadata, this, cNonce.value, proofSigner, ProofType.JWT),
                    )
                }
            }
            CredentialIssuanceRequest.BatchCredentials(credentialRequests)
        }
    }

    private fun CredentialIdentifier.matchIssuerSupportedCredential(): CredentialSupported {
        val credentialSupported = issuerMetadata.credentialsSupported[this]
        requireNotNull(credentialSupported)
        return credentialSupported
    }

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
