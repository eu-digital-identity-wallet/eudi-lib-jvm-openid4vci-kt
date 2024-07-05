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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance
import eu.europa.ec.eudi.openid4vci.internal.http.BatchEndPointClient
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialEndpointClient

/**
 * Models a response of the issuer to a successful issuance request.
 *
 * @param credentials The outcome of the issuance request.
 * if the issuance request was a batch request, it will contain
 * the results of each issuance request.
 * If it was a single issuance request list will contain only one result.
 * @param cNonce Nonce information sent back from the issuance server.
 */
internal data class CredentialIssuanceResponse(
    val credentials: List<IssuedCredential>,
    val cNonce: CNonce?,
)

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    private val credentialEndpointClient: CredentialEndpointClient,
    private val batchEndPointClient: BatchEndPointClient?,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : RequestIssuance, RequestBatchIssuance {

    override suspend fun AuthorizedRequest.requestSingleAndUpdateState(
        requestPayload: IssuanceRequestPayload,
        popSigner: PopSigner?,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        //
        // Place the request
        //
        val outcome = placeIssuanceRequest(accessToken) {
            val proofFactory = when (this) {
                is AuthorizedRequest.NoProofRequired -> null
                is AuthorizedRequest.ProofRequired -> {
                    requireNotNull(popSigner) { "PopSigner is required in Authorized.ProofRequired" }
                    proofFactory(popSigner, cNonce)
                }
            }
            singleRequest(requestPayload, proofFactory, credentialIdentifiers)
        }

        //
        // Update state
        //
        val updatedAuthorizedRequest = this.withCNonceFrom(outcome)

        //
        // Retry on invalid proof if we begin from NoProofRequired and issuer
        // replied with InvalidProof
        //
        val retryOnInvalidProof =
            this is AuthorizedRequest.NoProofRequired &&
                popSigner != null &&
                updatedAuthorizedRequest is AuthorizedRequest.ProofRequired &&
                outcome is SubmissionOutcomeInternal.InvalidProof

        suspend fun retry() =
            updatedAuthorizedRequest.requestSingleAndUpdateState(requestPayload, popSigner).getOrThrow()

        if (retryOnInvalidProof) retry()
        else updatedAuthorizedRequest to outcome.toPub()
    }

    private fun AuthorizedRequest.withCNonceFrom(outcome: SubmissionOutcomeInternal): AuthorizedRequest {
        val updated =
            when (outcome) {
                is SubmissionOutcomeInternal.Failed -> null
                is SubmissionOutcomeInternal.InvalidProof -> withCNonce(outcome.cNonce)
                is SubmissionOutcomeInternal.Success -> outcome.cNonce?.let { withCNonce(it) }
            }
        return updated ?: this
    }

    override suspend fun AuthorizedRequest.requestBatchAndUpdateState(
        credentialsMetadata: List<Pair<IssuanceRequestPayload, PopSigner?>>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        //
        // Place the request
        //
        val outcome = placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (requestPayload, popSigner) ->
                val proofFactory = when (this) {
                    is AuthorizedRequest.NoProofRequired -> null
                    is AuthorizedRequest.ProofRequired -> {
                        requireNotNull(popSigner) { "PopSigner is required in Authorized.ProofRequired" }
                        proofFactory(popSigner, cNonce)
                    }
                }
                singleRequest(requestPayload, proofFactory, credentialIdentifiers, true)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests, responseEncryptionSpec)
        }

        //
        // Update state
        //
        val updatedAuthorizedRequest = this.withCNonceFrom(outcome)

        //
        // Retry on invalid proof if we begin from NoProofRequired and issuer
        // replied with InvalidProof
        //
        val retryOnInvalidProof =
            this is AuthorizedRequest.NoProofRequired &&
                updatedAuthorizedRequest is AuthorizedRequest.ProofRequired &&
                outcome is SubmissionOutcomeInternal.InvalidProof

        suspend fun retry() =
            updatedAuthorizedRequest.requestBatchAndUpdateState(credentialsMetadata).getOrThrow()

        if (retryOnInvalidProof) retry()
        else updatedAuthorizedRequest to outcome.toPub()
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private suspend fun proofFactory(proofSigner: PopSigner, cNonce: CNonce): ProofFactory = { credentialSupported ->
        val iss = config.clientId
        val aud = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier
        val proofTypesSupported = credentialSupported.proofTypesSupported
        ProofBuilder(proofTypesSupported, config.clock, iss, aud, cNonce, proofSigner).build()
    }

    private suspend fun singleRequest(
        requestPayload: IssuanceRequestPayload,
        proofFactory: ProofFactory?,
        credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
        partOfBatch: Boolean = false,
    ): CredentialIssuanceRequest.SingleRequest {
        val includeEncryptionSpec = !partOfBatch
        return when (requestPayload) {
            is IssuanceRequestPayload.ConfigurationBased -> {
                formatBasedRequest(
                    requestPayload.credentialConfigurationIdentifier,
                    requestPayload.claimSet,
                    proofFactory,
                    includeEncryptionSpec,
                )
            }

            is IssuanceRequestPayload.IdentifierBased -> {
                val (credentialConfigurationId, credentialId) = requestPayload
                require(
                    credentialIdentifiers != null &&
                        credentialIdentifiers[credentialConfigurationId]?.contains(credentialId) ?: false,
                ) {
                    "The credential identifier passed is not valid or unknown"
                }
                identifierBasedRequest(credentialConfigurationId, credentialId, proofFactory, includeEncryptionSpec)
            }
        }
    }

    private suspend fun formatBasedRequest(
        credentialConfigurationId: CredentialConfigurationIdentifier,
        claimSet: ClaimSet?,
        proofFactory: ProofFactory?,
        includeEncryptionSpec: Boolean,
    ): CredentialIssuanceRequest.FormatBased {
        require(credentialOffer.credentialConfigurationIdentifiers.contains(credentialConfigurationId)) {
            "The requested credential is not authorized for issuance"
        }
        val credentialSupported = credentialSupportedById(credentialConfigurationId)
        val proof = proofFactory?.invoke(credentialSupported)?.also { assertProofSupported(it, credentialSupported) }
        return CredentialIssuanceRequest.formatBased(
            credentialSupported,
            claimSet,
            proof,
            responseEncryptionSpec.takeIf { includeEncryptionSpec },
        )
    }

    private suspend fun identifierBasedRequest(
        credentialConfigurationId: CredentialConfigurationIdentifier,
        credentialId: CredentialIdentifier,
        proofFactory: ProofFactory?,
        includeEncryptionSpec: Boolean,
    ): CredentialIssuanceRequest.IdentifierBased {
        require(credentialOffer.credentialConfigurationIdentifiers.contains(credentialConfigurationId)) {
            "The requested credential is not authorized for issuance"
        }
        val credentialSupported = credentialSupportedById(credentialConfigurationId)
        val proof = proofFactory?.invoke(credentialSupported)?.also { assertProofSupported(it, credentialSupported) }
        return CredentialIssuanceRequest.IdentifierBased(
            credentialId,
            proof,
            responseEncryptionSpec.takeIf { includeEncryptionSpec },
        )
    }

    private fun assertProofSupported(p: Proof, credentialSupported: CredentialConfiguration) {
        val proofType = when (p) {
            is Proof.Jwt -> ProofType.JWT
            is Proof.Cwt -> ProofType.CWT
            is Proof.LdpVp -> ProofType.LDP_VP
        }
        requireNotNull(credentialSupported.proofTypesSupported[proofType]) {
            "Provided proof type $proofType is not one of supported [${credentialSupported.proofTypesSupported}]."
        }
    }

    private suspend fun placeIssuanceRequest(
        token: AccessToken,
        issuanceRequestSupplier: suspend () -> CredentialIssuanceRequest,
    ): SubmissionOutcomeInternal {
        fun handleIssuanceFailure(error: Throwable): SubmissionOutcomeInternal.Errored =
            submitRequestFromError(error) ?: throw error
        return when (val credentialRequest = issuanceRequestSupplier()) {
            is CredentialIssuanceRequest.SingleRequest -> {
                credentialEndpointClient.placeIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmissionOutcomeInternal.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }

            is CredentialIssuanceRequest.BatchRequest -> {
                ensureNotNull(batchEndPointClient) { IssuerDoesNotSupportBatchIssuance() }
                batchEndPointClient.placeBatchIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmissionOutcomeInternal.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }
        }
    }
}

private fun submitRequestFromError(error: Throwable): SubmissionOutcomeInternal.Errored? = when (error) {
    is CredentialIssuanceError.InvalidProof ->
        SubmissionOutcomeInternal.InvalidProof(CNonce(error.cNonce, error.cNonceExpiresIn), error.errorDescription)

    is CredentialIssuanceError -> SubmissionOutcomeInternal.Failed(error)
    else -> null
}

private sealed interface SubmissionOutcomeInternal {

    data class Success(
        val credentials: List<IssuedCredential>,
        val cNonce: CNonce?,
    ) : SubmissionOutcomeInternal

    sealed interface Errored : SubmissionOutcomeInternal
    data class Failed(
        val error: CredentialIssuanceError,
    ) : Errored

    data class InvalidProof(
        val cNonce: CNonce,
        val errorDescription: String? = null,
    ) : Errored

    fun toPub(): SubmissionOutcome =
        when (this) {
            is Success -> SubmissionOutcome.Success(credentials, cNonce)
            is Failed -> SubmissionOutcome.Failed(error)
            is InvalidProof -> SubmissionOutcome.InvalidProof(cNonce, errorDescription)
        }
}
