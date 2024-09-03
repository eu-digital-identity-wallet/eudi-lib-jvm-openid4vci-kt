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
    private val batchCredentialIssuance: BatchCredentialIssuance?,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : RequestIssuance {

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        popSigners: List<PopSigner>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        //
        // Place the request
        //
        val outcome = placeIssuanceRequest(accessToken) {
            val proofFactories = proofFactoriesForm(popSigners)
            buildRequest(requestPayload, proofFactories, credentialIdentifiers)
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
                popSigners.isNotEmpty() &&
                updatedAuthorizedRequest is AuthorizedRequest.ProofRequired &&
                outcome.isInvalidProof()

        suspend fun retry() =
            updatedAuthorizedRequest.request(requestPayload, popSigners)
                .getOrThrow()
                .markInvalidProofIrrecoverable()

        if (retryOnInvalidProof) retry()
        else updatedAuthorizedRequest to outcome.toPub()
    }

    private fun AuthorizedRequest.withCNonceFrom(outcome: SubmissionOutcomeInternal): AuthorizedRequest {
        val updated =
            when (outcome) {
                is SubmissionOutcomeInternal.Failed ->
                    outcome.cNonceFromInvalidProof()?.let { newCNonce -> withCNonce(newCNonce) }

                is SubmissionOutcomeInternal.Success ->
                    outcome.cNonce?.let { withCNonce(it) }
            }
        return updated ?: this
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private fun AuthorizedRequest.proofFactoriesForm(popSigners: List<PopSigner>): List<ProofFactory> =
        when (this) {
            is AuthorizedRequest.NoProofRequired -> emptyList()
            is AuthorizedRequest.ProofRequired -> {
                when (val popSignersNo = popSigners.size) {
                    0 -> error("At least a PopSigner is required in Authorized.ProofRequired")
                    1 -> Unit
                    else -> {
                        ensureNotNull(batchCredentialIssuance) {
                            CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance()
                        }
                        val maxBatchSize = batchCredentialIssuance.batchSize
                        ensure(popSignersNo <= maxBatchSize) {
                            CredentialIssuanceError.IssuerBatchSizeLimitExceeded(maxBatchSize)
                        }
                    }
                }
                popSigners.map { proofFactory(it, cNonce) }
            }
        }

    private fun proofFactory(proofSigner: PopSigner, cNonce: CNonce): ProofFactory = { credentialSupported ->
        val iss = config.client.id
        val aud = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier
        val proofTypesSupported = credentialSupported.proofTypesSupported
        ProofBuilder(proofTypesSupported, config.clock, iss, aud, cNonce, proofSigner).build()
    }

    private suspend fun buildRequest(
        requestPayload: IssuanceRequestPayload,
        proofFactories: List<ProofFactory>,
        credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
    ): CredentialIssuanceRequest {
        val credentialCfg = run {
            val creCfgId = requestPayload.credentialConfigurationIdentifier
            check(creCfgId in credentialOffer.credentialConfigurationIdentifiers) {
                "The provided credential configuration ${creCfgId.value} is not part of the credential offer"
            }
            credentialSupportedById(creCfgId)
        }

        val proofs = proofFactories.map { factory ->
            factory(credentialCfg).also(credentialCfg::assertProofSupported)
        }

        return when (requestPayload) {
            is IssuanceRequestPayload.ConfigurationBased -> {
                CredentialIssuanceRequest.formatBased(
                    credentialCfg,
                    requestPayload.claimSet,
                    proofs,
                    responseEncryptionSpec,
                )
            }
            is IssuanceRequestPayload.IdentifierBased -> {
                if (credentialIdentifiers != null) {
                    requestPayload.ensureAuthorized(credentialIdentifiers)
                }
                CredentialIssuanceRequest.byId(requestPayload.credentialIdentifier, proofs, responseEncryptionSpec)
            }
        }
    }

    private suspend fun placeIssuanceRequest(
        token: AccessToken,
        issuanceRequestSupplier: suspend () -> CredentialIssuanceRequest,
    ): SubmissionOutcomeInternal {
        fun handleIssuanceFailure(error: Throwable): SubmissionOutcomeInternal.Failed =
            SubmissionOutcomeInternal.fromThrowable(error) ?: throw error

        val credentialRequest = issuanceRequestSupplier()
        return credentialEndpointClient.placeIssuanceRequest(token, credentialRequest).fold(
            onSuccess = { SubmissionOutcomeInternal.Success(it.credentials, it.cNonce) },
            onFailure = { handleIssuanceFailure(it) },
        )
    }
}

private fun IssuanceRequestPayload.IdentifierBased.ensureAuthorized(
    credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
) {
    val credentialId = credentialIdentifier
    val authorizedCredIds = checkNotNull(credentialIdentifiers[credentialConfigurationIdentifier]) {
        "No credential identifiers authorized for $credentialConfigurationIdentifier"
    }
    check(credentialId in authorizedCredIds) {
        "The credential identifier ${credentialId.value} is not authorized"
    }
}

private fun CredentialConfiguration.assertProofSupported(proof: Proof) {
    val proofType = when (proof) {
        is Proof.Jwt -> ProofType.JWT
        is Proof.LdpVp -> ProofType.LDP_VP
    }
    checkNotNull(proofTypesSupported[proofType]) {
        "Provided proof type $proofType is not one of supported [$proofTypesSupported]."
    }
}

private sealed interface SubmissionOutcomeInternal {

    data class Success(
        val credentials: List<IssuedCredential>,
        val cNonce: CNonce?,
    ) : SubmissionOutcomeInternal

    data class Failed(
        val error: CredentialIssuanceError,
    ) : SubmissionOutcomeInternal

    fun toPub(): SubmissionOutcome =
        when (this) {
            is Success -> SubmissionOutcome.Success(credentials)
            is Failed -> SubmissionOutcome.Failed(error)
        }

    fun isInvalidProof(): Boolean =
        null != cNonceFromInvalidProof()

    fun cNonceFromInvalidProof(): CNonce? =
        if (this is Failed && error is CredentialIssuanceError.InvalidProof) {
            CNonce(error.cNonce, error.cNonceExpiresIn)
        } else null

    companion object {
        fun fromThrowable(error: Throwable): Failed? =
            when (error) {
                is CredentialIssuanceError -> Failed(error)
                else -> null
            }
    }
}

private fun AuthorizedRequestAnd<SubmissionOutcome>.markInvalidProofIrrecoverable() =
    first to when (val outcome = second) {
        is SubmissionOutcome.Failed ->
            if (outcome.error is CredentialIssuanceError.InvalidProof) {
                SubmissionOutcome.Failed(outcome.error.irrecoverbale())
            } else outcome

        is SubmissionOutcome.Success -> outcome
    }

private fun CredentialIssuanceError.InvalidProof.irrecoverbale() =
    CredentialIssuanceError.IrrecoverableInvalidProof(errorDescription)
