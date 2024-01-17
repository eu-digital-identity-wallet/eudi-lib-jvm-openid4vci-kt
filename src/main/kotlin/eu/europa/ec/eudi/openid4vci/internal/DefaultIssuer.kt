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
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.NoProofRequired
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest.ProofRequired
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
import eu.europa.ec.eudi.openid4vci.UnauthorizedRequest.AuthorizationCodeRetrieved
import eu.europa.ec.eudi.openid4vci.UnauthorizedRequest.ParRequested
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest.BatchRequest

private typealias ProofFactory = (CredentialSupported) -> Proof

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
internal class DefaultIssuer(
    private val issuerMetadata: CredentialIssuerMetadata,
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
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
    ): Result<ParRequested> = runCatching {
        val (codeVerifier, authorizationCodeUrl) = run {
            val scopes = credentials.mapNotNull { credentialId ->
                credentialSupportedById(credentialId).scope?.let { Scope(it) }
            }
            val state = State().value
            authorizer.submitPushedAuthorizationRequest(scopes, state, issuerState).getOrThrow()
        }
        ParRequested(authorizationCodeUrl, codeVerifier)
    }

    override suspend fun ParRequested.handleAuthorizationCode(
        authorizationCode: AuthorizationCode,
    ): AuthorizationCodeRetrieved = AuthorizationCodeRetrieved(authorizationCode, pkceVerifier)

    override suspend fun AuthorizationCodeRetrieved.requestAccessToken(): Result<AuthorizedRequest> =
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

    override suspend fun NoProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) { singleRequest(credentialId, claimSet, null) }
    }

    override suspend fun ProofRequired.requestSingle(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        proofSigner: ProofSigner,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            singleRequest(credentialId, claimSet, proofFactory(proofSigner, cNonce))
        }
    }

    override suspend fun NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<CredentialIdentifier, ClaimSet?>>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (credentialId, claimSet) ->
                singleRequest(credentialId, claimSet, null)
            }
            BatchRequest(credentialRequests)
        }
    }

    override suspend fun ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<CredentialIdentifier, ClaimSet?, ProofSigner>>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (credentialId, claimSet, proofSigner) ->
                singleRequest(credentialId, claimSet, proofFactory(proofSigner, cNonce))
            }
            BatchRequest(credentialRequests)
        }
    }

    private fun credentialSupportedById(credentialId: CredentialIdentifier): CredentialSupported {
        val credentialSupported = issuerMetadata.credentialsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private fun proofFactory(proofSigner: ProofSigner, cNonce: CNonce): ProofFactory = { credentialSupported ->
        ProofBuilder.ofType(ProofType.JWT) {
            aud(issuerMetadata.credentialIssuerIdentifier.toString())
            publicKey(proofSigner.getBindingKey())
            credentialSpec(credentialSupported)
            nonce(cNonce.value)
            build(proofSigner)
        }
    }

    private fun singleRequest(
        credentialId: CredentialIdentifier,
        claimSet: ClaimSet?,
        proofFactory: ProofFactory?,
    ): CredentialIssuanceRequest.SingleRequest {
        val credentialSupported = credentialSupportedById(credentialId)
        fun assertSupported(p: Proof) {
            val proofType = when (p) {
                is Proof.Jwt -> ProofType.JWT
                is Proof.Cwt -> ProofType.CWT
            }
            require(proofType in credentialSupported.proofTypesSupported) {
                "Provided proof type $proofType is not one of supported [${credentialSupported.proofTypesSupported}]."
            }
        }
        val proof = proofFactory?.invoke(credentialSupported)?.also { assertSupported(it) }
        return CredentialIssuanceRequest.singleRequest(credentialSupported, claimSet, proof, responseEncryptionSpec)
    }

    override suspend fun NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): ProofRequired = ProofRequired(accessToken, cNonce)

    override suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<DeferredCredentialQueryOutcome> =
        issuanceRequester.placeDeferredCredentialRequest(accessToken, deferredCredential.transactionId)

    private suspend fun placeIssuanceRequest(
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

            is BatchRequest -> {
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
