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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialEndpointClient
import eu.europa.ec.eudi.openid4vci.internal.http.NonceEndpointClient
import java.time.Instant

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

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        proofsSpec: ProofsSpecification,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        val credentialConfigId = requestPayload.credentialConfigurationIdentifier

        // Place the request
        val (outcome, newResourceServerDpopNonce) = placeIssuanceRequest(accessToken, resourceServerDpopNonce) {
            when (proofsSpec) {
                is ProofsSpecification.NoProofs -> {
                    require(credentialConfigId.proofsRequirement() is CredentialProofsRequirement.ProofNotRequired) {
                        "Proofs are required for credential configuration $credentialConfigId, but proofs specification is set to NoProofs"
                    }
                    buildRequest(requestPayload, null, credentialIdentifiers.orEmpty())
                }
                is ProofsSpecification.JwtProofs.NoKeyAttestation -> {
                    ensure(
                        credentialConfigId.keyAttestationProofsRequirement() !is KeyAttestationRequirement.Required &&
                            credentialConfigId.keyAttestationProofsRequirement() !is KeyAttestationRequirement.RequiredNoConstraints,
                    ) {
                        CredentialIssuanceError.ProofTypeKeyAttestationRequired()
                    }

                    proofsSpec.proofsSigner.use { signOps ->
                        val javaAlgorithm = proofsSpec.proofsSigner.javaAlgorithm
                        val proofsFactory = jwtProofsFactoryFrom(signOps, javaAlgorithm, credentialConfigId)
                        buildRequest(requestPayload, proofsFactory, credentialIdentifiers.orEmpty())
                    }
                }
                is ProofsSpecification.JwtProofs.WithKeyAttestation -> {
                    proofsSpec.proofSigner.use { signOp ->
                        val javaAlgorithm = proofsSpec.proofSigner.javaAlgorithm
                        val keyIndex = proofsSpec.keyIndex
                        val proofsFactory = keyAttestationJwtProofFactoryFrom(signOp, keyIndex, javaAlgorithm, credentialConfigId)
                        buildRequest(requestPayload, proofsFactory, credentialIdentifiers.orEmpty())
                    }
                }
                is ProofsSpecification.AttestationProof -> error("Attestation proofs not yet supported")
            }
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

    private fun CredentialConfigurationIdentifier.keyAttestationProofsRequirement(): KeyAttestationRequirement {
        val credentialConfiguration = credentialSupportedById(this)
        val spec = credentialConfiguration.proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
        return when {
            spec == null -> KeyAttestationRequirement.NotRequired
            else -> spec.keyAttestationRequirement
        }
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private suspend fun AuthorizedRequest.keyAttestationJwtProofFactoryFrom(
        keyAttestationSigner: SignOperation<String>,
        keyIndex: Int,
        javaSigningAlgorithm: String,
        credentialConfigId: CredentialConfigurationIdentifier,
    ): ProofsFactory? {
        // Deduct from credential configuration and issuer metadata if issuer requires proofs to be sent for the specific credential
        val proofsRequirement = credentialConfigId.proofsRequirement()

        return when (proofsRequirement) {
            is CredentialProofsRequirement.ProofNotRequired -> null

            is CredentialProofsRequirement.ProofRequired -> {
                // Check signing algorithm compatibility
                val joseAlg = javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)

                val cNonce = proofsRequirement.cNonce()
                keyAttestationProofsFactory(
                    KeyAttestationJwtProofSigner(joseAlg, keyAttestationSigner, keyIndex),
                    cNonce,
                    grant,
                )
            }
        }
    }

    private suspend fun AuthorizedRequest.jwtProofsFactoryFrom(
        proofsSigner: BatchSignOperation<JwtBindingKey>,
        javaSigningAlgorithm: String,
        credentialConfigId: CredentialConfigurationIdentifier,
    ): ProofsFactory? {
        // Deduct from credential configuration and issuer metadata if issuer requires proofs to be sent for the specific credential
        val proofsRequirement = credentialConfigId.proofsRequirement()

        return when (proofsRequirement) {
            is CredentialProofsRequirement.ProofNotRequired -> null

            is CredentialProofsRequirement.ProofRequired -> {
                proofsSigner.assertMatchesBatchIssuanceBatchSize()

                // Check signing algorithm compatibility
                val joseAlg = javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)

                val cNonce = proofsRequirement.cNonce()
                val proofsSigner = JwtProofsSigner(joseAlg, proofsSigner)
                proofsFactory(proofsSigner, cNonce, grant)
            }
        }
    }

    private fun BatchSignOperation<JwtBindingKey>.assertMatchesBatchIssuanceBatchSize() =
        when (val popSignersNo = operations.size) {
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

    private fun String.toSupportedJoseAlgorithm(credentialConfigId: CredentialConfigurationIdentifier): JWSAlgorithm {
        val proofTypesSupported = credentialSupportedById(credentialConfigId).proofTypesSupported
        val spec = proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
        ensureNotNull(spec) {
            CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported()
        }
        return spec.let {
            val joseSigningAlgorithm = this.toJoseAlg()
            val proofTypeSigningAlgorithmsSupported = spec.algorithms
            ensure(joseSigningAlgorithm in proofTypeSigningAlgorithmsSupported) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported()
            }
            joseSigningAlgorithm
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

    private fun jwtProofClaims(
        cNonce: CNonce?,
        grant: Grant,
    ): JwtProofClaims {
        fun iss(client: Client, grant: Grant): ClientId? {
            val useIss = when (grant) {
                Grant.AuthorizationCode -> true
                Grant.PreAuthorizedCodeGrant -> when (client) {
                    is Client.Attested -> true
                    is Client.Public -> false
                }
            }
            return client.id.takeIf { useIss }
        }

        return JwtProofClaims(
            audience = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier.toString(),
            issuedAt = Instant.now(),
            issuer = iss(config.client, grant),
            nonce = cNonce?.value,
        )
    }

    private fun keyAttestationProofsFactory(
        proofsSigner: KeyAttestationJwtProofSigner,
        cNonce: CNonce?,
        grant: Grant,
    ): ProofsFactory = { credentialSupported ->
        val signedJwt = proofsSigner.sign(
            jwtProofClaims(
                cNonce = cNonce,
                grant = grant,
            ),
        )
        listOf(Proof.Jwt(SignedJWT.parse(signedJwt)))
    }

    private fun proofsFactory(
        proofsSigner: JwtProofsSigner,
        cNonce: CNonce?,
        grant: Grant,
    ): ProofsFactory = { credentialSupported ->
        proofsSigner.sign(
            jwtProofClaims(
                cNonce = cNonce,
                grant = grant,
            ),
        ).map {
            Proof.Jwt(SignedJWT.parse(it.second))
        }
    }

    private suspend fun buildRequest(
        requestPayload: IssuanceRequestPayload,
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

        val proofs = proofsFactory?.let {
            proofsFactory(credentialCfg)
        }?.also {
            it.forEach { proof -> credentialCfg.assertProofSupported(proof) }
        }
            ?: emptyList()

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
