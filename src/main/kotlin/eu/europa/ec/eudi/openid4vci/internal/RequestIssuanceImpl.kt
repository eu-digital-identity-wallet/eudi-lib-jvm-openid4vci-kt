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
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val issuerMetadata: CredentialIssuerMetadata,
    private val config: OpenId4VCIConfig,
    ktorHttpClientFactory: KtorHttpClientFactory,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
) : RequestIssuance {

    private val issuanceRequester: IssuanceRequester =
        IssuanceRequester(issuerMetadata, ktorHttpClientFactory)

    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec? by lazy {
        fun IssuanceResponseEncryptionSpec.validate(meta: CredentialResponseEncryption.Required) {
            ensure(algorithm in meta.algorithmsSupported) {
                CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
            }
            ensure(encryptionMethod in meta.encryptionMethodsSupported) {
                CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
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

    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
        claimSet: ClaimSet?,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            singleRequest(requestCredentialIdentifier, claimSet, null, credentialIdentifiers)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
        claimSet: ClaimSet?,
        proofSigner: ProofSigner,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            singleRequest(requestCredentialIdentifier, claimSet, proofFactory(proofSigner, cNonce), credentialIdentifiers)
        }
    }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<Pair<IssuanceRequestCredentialIdentifier, ClaimSet?>>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (credentialId, claimSet) ->
                singleRequest(credentialId, claimSet, null, credentialIdentifiers)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Triple<IssuanceRequestCredentialIdentifier, ClaimSet?, ProofSigner>>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (credentialId, claimSet, proofSigner) ->
                singleRequest(credentialId, claimSet, proofFactory(proofSigner, cNonce), credentialIdentifiers)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests)
        }
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported = issuerMetadata.credentialConfigurationsSupported[credentialId]
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
        requestCredentialIdentifier: IssuanceRequestCredentialIdentifier,
        claimSet: ClaimSet?,
        proofFactory: ProofFactory?,
        credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
    ): CredentialIssuanceRequest.SingleRequest {
        val (credentialConfigurationId, credentialId) = requestCredentialIdentifier
        return credentialId?.let {
            require(credentialIdentifiers != null && credentialIdentifiers[credentialConfigurationId]?.contains(credentialId) ?: false) {
                "The credential identifier passed is not valid or unknown"
            }
            identifierBasedRequest(credentialConfigurationId to credentialId, proofFactory)
        }
            ?: formatBasedRequest(requestCredentialIdentifier.first, claimSet, proofFactory)
    }

    private fun formatBasedRequest(
        credentialConfigurationId: CredentialConfigurationIdentifier,
        claimSet: ClaimSet?,
        proofFactory: ProofFactory?,
    ): CredentialIssuanceRequest.FormatBased {
        require(credentialOffer.credentialConfigurationIdentifiers.contains(credentialConfigurationId)) {
            "The requested credential is not authorized for issuance"
        }
        val credentialSupported = credentialSupportedById(credentialConfigurationId)
        val proof = proofFactory?.invoke(credentialSupported)?.also { assertProofSupported(it, credentialSupported) }
        return CredentialIssuanceRequest.formatBased(credentialSupported, claimSet, proof, responseEncryptionSpec)
    }

    private fun identifierBasedRequest(
        requestCredentialIdentifier: Pair<CredentialConfigurationIdentifier, CredentialIdentifier>,
        proofFactory: ProofFactory?,
    ): CredentialIssuanceRequest.IdentifierBased {
        val (credentialConfigurationId, credentialId) = requestCredentialIdentifier
        require(credentialOffer.credentialConfigurationIdentifiers.contains(credentialConfigurationId)) {
            "The requested credential is not authorized for issuance"
        }
        // TODO: Check if credentialId is in the list of identifiers retrieved from token endpoint ??? Maybe too strict
        val credentialSupported = credentialSupportedById(credentialConfigurationId)
        val proof = proofFactory?.invoke(credentialSupported)?.also { assertProofSupported(it, credentialSupported) }
        return CredentialIssuanceRequest.IdentifierBased(credentialId, proof, responseEncryptionSpec)
    }

    private fun assertProofSupported(p: Proof, credentialSupported: CredentialConfiguration) {
        val proofType = when (p) {
            is Proof.Jwt -> ProofType.JWT
            is Proof.Cwt -> ProofType.CWT
            is Proof.LdpVp -> ProofType.LDP_VP
        }
        require(proofType in credentialSupported.proofTypesSupported.keys) {
            "Provided proof type $proofType is not one of supported [${credentialSupported.proofTypesSupported}]."
        }
    }

    override suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired = AuthorizedRequest.ProofRequired(accessToken, cNonce, credentialIdentifiers)

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
