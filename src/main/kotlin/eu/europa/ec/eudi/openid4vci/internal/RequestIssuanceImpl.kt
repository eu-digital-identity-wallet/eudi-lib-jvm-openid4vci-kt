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
import eu.europa.ec.eudi.openid4vci.internal.http.NonceEndpointClient
import java.util.Date

private sealed interface CredentialProofsRequirement {

    data object ProofNotRequired : CredentialProofsRequirement

    sealed interface ProofRequired : CredentialProofsRequirement {

        data object WithoutCNonce : ProofRequired

        data object WithCNonce : ProofRequired
    }
}

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    private val credentialEndpointClient: CredentialEndpointClient,
    private val nonceEndpointClient: NonceEndpointClient?,
    private val batchCredentialIssuance: BatchCredentialIssuance,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : RequestIssuance {

    init {
        val nonceEndpoint = credentialOffer.credentialIssuerMetadata.nonceEndpoint
        if (nonceEndpoint != null && nonceEndpointClient == null) {
            throw IllegalStateException("A nonce endpoint client needs to be configured if issuer advertises a nonce endpoint")
        }
        if (nonceEndpoint == null && nonceEndpointClient != null) {
            throw IllegalStateException("A nonce endpoint client is configured although issuer does not advertises a nonce endpoint")
        }
    }

    @Deprecated("Use the version with JwtProofsSigner instead", ReplaceWith("request(requestPayload, proofsSigner)"))
    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        popSigners: List<PopSigner>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        val credentialConfigId = requestPayload.credentialConfigurationIdentifier

        // Deduct from credential configuration and issuer metadata if issuer requires proofs to be sent for the specific credential
        val proofsRequirement = credentialConfigId.proofsRequirement()

        // Place the request
        val (outcome, newResourceServerDpopNonce) = placeIssuanceRequest(accessToken, resourceServerDpopNonce) {
            val proofFactories = proofFactoriesFrom(popSigners, proofsRequirement)
            buildRequest(requestPayload, proofFactories, null, credentialIdentifiers.orEmpty())
        }

        // Update state (maybe) with new Dpop Nonce from resource server
        val updatedAuthorizedRequest = this.withResourceServerDpopNonce(newResourceServerDpopNonce)
        updatedAuthorizedRequest to outcome.toPub()
    }

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        proofsSigner: JwtProofsSigner?,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        val credentialConfigId = requestPayload.credentialConfigurationIdentifier

        // Deduct from credential configuration and issuer metadata if issuer requires proofs to be sent for the specific credential
        val proofsRequirement = credentialConfigId.proofsRequirement()

        // Place the request
        val (outcome, newResourceServerDpopNonce) = placeIssuanceRequest(accessToken, resourceServerDpopNonce) {
            val proofsFactory = proofsFactoryFrom(proofsSigner, proofsRequirement)
            buildRequest(requestPayload, null, proofsFactory, credentialIdentifiers.orEmpty())
        }

        // Update state (maybe) with new Dpop Nonce from resource server
        val updatedAuthorizedRequest = this.withResourceServerDpopNonce(newResourceServerDpopNonce)
        updatedAuthorizedRequest to outcome.toPub()
    }

    private fun CredentialConfigurationIdentifier.proofsRequirement(): CredentialProofsRequirement {
        val credentialIssuerMetadata = credentialOffer.credentialIssuerMetadata
        val credentialConfiguration = credentialSupportedById(this)
        return when {
            credentialConfiguration.proofTypesSupported.values.isEmpty() -> CredentialProofsRequirement.ProofNotRequired
            credentialIssuerMetadata.nonceEndpoint == null -> CredentialProofsRequirement.ProofRequired.WithoutCNonce
            else -> CredentialProofsRequirement.ProofRequired.WithCNonce
        }
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private suspend fun AuthorizedRequest.proofFactoriesFrom(
        popSigners: List<PopSigner>,
        proofsRequirement: CredentialProofsRequirement,
    ): List<ProofFactory> =
        when (proofsRequirement) {
            is CredentialProofsRequirement.ProofNotRequired -> emptyList()
            is CredentialProofsRequirement.ProofRequired -> {
                when (val popSignersNo = popSigners.size) {
                    0 -> error("At least one PopSigner is required in Authorized.ProofRequired")
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
                val cNonce = proofsRequirement.cNonce()
                popSigners.map { proofFactory(it, cNonce, grant) }
            }
        }

    private suspend fun AuthorizedRequest.proofsFactoryFrom(
        proofsSigner: JwtProofsSigner?,
        proofsRequirement: CredentialProofsRequirement,
    ): ProofsFactory? =
        when (proofsRequirement) {
            is CredentialProofsRequirement.ProofNotRequired -> null
            is CredentialProofsRequirement.ProofRequired -> {
                val cNonce = proofsRequirement.cNonce()
                requireNotNull(proofsSigner) {
                    "A JwtProofsSigner is required when proofs are required: $proofsRequirement"
                }
                proofsFactory(
                    proofsSigner,
                    cNonce,
                    grant,
                )
            }
        }

    private suspend fun CredentialProofsRequirement.ProofRequired.cNonce(): CNonce? =
        when (this) {
            CredentialProofsRequirement.ProofRequired.WithoutCNonce -> null
            CredentialProofsRequirement.ProofRequired.WithCNonce -> {
                checkNotNull(nonceEndpointClient) { "Issuer does not provide nonce endpoint." }
                nonceEndpointClient.getNonce().getOrThrow()
            }
        }

    private fun proofFactory(
        proofSigner: PopSigner,
        cNonce: CNonce?,
        grant: Grant,
    ): ProofFactory = { credentialSupported ->
        val aud = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier
        val proofTypesSupported = credentialSupported.proofTypesSupported
        ProofBuilder(proofTypesSupported, config.clock, config.client, grant, aud, cNonce, proofSigner).build()
    }

    private fun proofsFactory(
        proofsSigner: JwtProofsSigner,
        cNonce: CNonce?,
        grant: Grant,
    ): ProofsFactory = { credentialSupported ->
        val aud = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier
        val proofTypesSupported = credentialSupported.proofTypesSupported
        proofsSigner.sign(
            JwtProofClaims(
                audience = aud.toString(),
                issuedAt = Date(),
                issuer = null, // TODO GD
                nonce = cNonce?.value,
            ),
        ).map {
            Proof.Jwt(it.second)
        }
    }

    private suspend fun buildRequest(
        requestPayload: IssuanceRequestPayload,
        proofFactories: List<ProofFactory>?,
        proofsFactory: ProofsFactory?,
        authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
    ): CredentialIssuanceRequest {
        val credentialCfg = run {
            val creCfgId = requestPayload.credentialConfigurationIdentifier
            check(creCfgId in credentialOffer.credentialConfigurationIdentifiers) {
                "The provided credential configuration ${creCfgId.value} is not part of the credential offer"
            }
            credentialSupportedById(creCfgId)
        }

        var proofs = proofFactories?.let {
            it.map { factory ->
                factory(credentialCfg).also(credentialCfg::assertProofSupported)
            }
        }

        proofsFactory?.let {
            proofs = proofsFactory(credentialCfg) // TODO GD check also credentialCfg::assertProofSupported
        }

        return when (requestPayload) {
            is IssuanceRequestPayload.ConfigurationBased -> {
                CredentialIssuanceRequest.byCredentialConfigurationId(
                    requestPayload.credentialConfigurationIdentifier,
                    proofs!!,
                    responseEncryptionSpec,
                )
            }

            is IssuanceRequestPayload.IdentifierBased -> {
                requestPayload.ensureAuthorized(authorizationDetails)
                CredentialIssuanceRequest.byCredentialId(
                    requestPayload.credentialIdentifier,
                    proofs!!,
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
        val notificationId: NotificationId?,
    ) : SubmissionOutcomeInternal

    data class Deferred(
        val transactionId: TransactionId,
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
}
