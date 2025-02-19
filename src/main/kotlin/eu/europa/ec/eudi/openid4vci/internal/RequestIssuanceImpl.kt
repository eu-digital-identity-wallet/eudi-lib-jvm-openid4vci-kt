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

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    private val credentialEndpointClient: CredentialEndpointClient,
    private val batchCredentialIssuance: BatchCredentialIssuance,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : RequestIssuance {

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        popSigners: List<PopSigner>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        //
        // Place the request
        //
        val (outcome, newResourceServerDpopNonce) = placeIssuanceRequest(accessToken, resourceServerDpopNonce) {
            val proofFactories = proofFactoriesForm(popSigners)
            buildRequest(requestPayload, proofFactories, credentialIdentifiers.orEmpty())
        }

        //
        // Update state
        //
        val updatedAuthorizedRequest =
            this.withCNonceFrom(outcome).withResourceServerDpopNonce(newResourceServerDpopNonce)

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

                is SubmissionOutcomeInternal.Deferred ->
                    outcome.cNonce?.let { withCNonce(it) }

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
                        when (batchCredentialIssuance) {
                            BatchCredentialIssuance.NotSupported -> CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance()
                            is BatchCredentialIssuance.Supported -> {
                                val maxBatchSize = batchCredentialIssuance.batchSize
                                ensure(popSignersNo <= maxBatchSize) {
                                    CredentialIssuanceError.IssuerBatchSizeLimitExceeded(maxBatchSize)
                                }
                            }
                        }
                    }
                }
                popSigners.map { proofFactory(it, cNonce, grant) }
            }
        }

    private fun proofFactory(
        proofSigner: PopSigner,
        cNonce: CNonce,
        grant: Grant,
    ): ProofFactory = { credentialSupported ->
        val aud = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier
        val proofTypesSupported = credentialSupported.proofTypesSupported
        ProofBuilder(proofTypesSupported, config.clock, config.client, grant, aud, cNonce, proofSigner).build()
    }

    private suspend fun buildRequest(
        requestPayload: IssuanceRequestPayload,
        proofFactories: List<ProofFactory>,
        authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
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
                CredentialIssuanceRequest.byCredentialConfigurationId(
                    requestPayload.credentialConfigurationIdentifier,
                    proofs,
                    responseEncryptionSpec,
                )
            }

            is IssuanceRequestPayload.IdentifierBased -> {
                requestPayload.ensureAuthorized(authorizationDetails)
                CredentialIssuanceRequest.byCredentialId(
                    requestPayload.credentialIdentifier,
                    proofs,
                    responseEncryptionSpec,
                )
            }
        }
    }

    private suspend fun placeIssuanceRequest(
        token: AccessToken,
        resourceServerDpopNonce: Nonce?,
        issuanceRequestSupplier: suspend () -> CredentialIssuanceRequest,
    ): Pair<SubmissionOutcomeInternal, Nonce?> {
        val req = issuanceRequestSupplier()
        val res = credentialEndpointClient.placeIssuanceRequest(token, resourceServerDpopNonce, req)
        return res.getOrThrow()
    }
}

private fun IssuanceRequestPayload.IdentifierBased.ensureAuthorized(
    authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
) {
    val credentialId = credentialIdentifier
    val authorizedCredIds = checkNotNull(authorizationDetails[credentialConfigurationIdentifier]) {
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

internal sealed interface SubmissionOutcomeInternal {

    data class Success(
        val credentials: List<IssuedCredential>,
        val cNonce: CNonce?,
        val notificationId: NotificationId?,
    ) : SubmissionOutcomeInternal

    data class Deferred(
        val transactionId: TransactionId,
        val cNonce: CNonce?,
    ) : SubmissionOutcomeInternal

    data class Failed(
        val error: CredentialIssuanceError,
    ) : SubmissionOutcomeInternal

    fun toPub(): SubmissionOutcome =
        when (this) {
            is Success -> SubmissionOutcome.Success(credentials, notificationId)
            is Deferred -> SubmissionOutcome.Deferred(transactionId)
            is Failed -> SubmissionOutcome.Failed(error)
        }

    fun isInvalidProof(): Boolean =
        null != cNonceFromInvalidProof()

    fun cNonceFromInvalidProof(): CNonce? =
        if (this is Failed && error is CredentialIssuanceError.InvalidProof) {
            CNonce(error.cNonce, error.cNonceExpiresIn)
        } else null
}

private fun AuthorizedRequestAnd<SubmissionOutcome>.markInvalidProofIrrecoverable() =
    first to when (val outcome = second) {
        is SubmissionOutcome.Failed ->
            if (outcome.error is CredentialIssuanceError.InvalidProof) {
                SubmissionOutcome.Failed(outcome.error.irrecoverable())
            } else outcome

        is SubmissionOutcome.Success -> outcome
        is SubmissionOutcome.Deferred -> outcome
    }

private fun CredentialIssuanceError.InvalidProof.irrecoverable() =
    CredentialIssuanceError.IrrecoverableInvalidProof(errorDescription)
