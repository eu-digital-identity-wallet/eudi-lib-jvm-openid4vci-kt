/*
 * Copyright (c) 2023-2026 European Commission
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
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CNonceAndDPoPNonce
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialEndpointClient
import eu.europa.ec.eudi.openid4vci.internal.http.NonceEndpointClient
import java.time.Instant
import kotlin.time.Duration

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val config: OpenId4VCIConfig,
    private val credentialEndpointClient: CredentialEndpointClient,
    private val nonceEndpointClient: NonceEndpointClient?,
    private val batchCredentialIssuance: BatchCredentialIssuance,
    private val exchangeEncryptionSpecification: ExchangeEncryptionSpecification,
) : RequestIssuance {

    init {
        val nonceEndpoint = credentialOffer.credentialIssuerMetadata.nonceEndpoint
        if (nonceEndpoint != null) {
            check(nonceEndpointClient != null) {
                " A nonce endpoint client needs to be configured if issuer advertises a nonce endpoint"
            }
        }
        if (nonceEndpointClient != null) {
            check(nonceEndpoint != null) {
                "A nonce endpoint client is configured although issuer does not advertises a nonce endpoint"
            }
        }
    }

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        proofsSpecification: ProofsSpecification,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatchingCancellable {
        validateRequestPayload(requestPayload, credentialIdentifiers.orEmpty())
        val credentialConfiguration = credentialSupportedById(requestPayload.credentialConfigurationIdentifier)
        val selectedCredentialReusePolicy = selectCredentialReusePolicy(credentialConfiguration)

        val (proofs, proofsDpopNonce) = buildProofs(
            proofsSpecification,
            selectedCredentialReusePolicy,
            requestPayload.credentialConfigurationIdentifier,
            grant,
        )
        val credentialRequest = buildRequest(requestPayload, proofs, credentialIdentifiers.orEmpty())

        // Place the request
        val proofsOrAuthRequestDpopNonce = proofsDpopNonce ?: resourceServerDpopNonce
        val (outcome, newResourceServerDpopNonce) =
            credentialEndpointClient.placeIssuanceRequest(
                accessToken,
                proofsOrAuthRequestDpopNonce,
                credentialRequest,
            ).getOrThrow()

        // Update state (maybe) with new Dpop Nonce from resource server
        val updatedAuthorizedRequest =
            this.withResourceServerDpopNonce(newResourceServerDpopNonce ?: proofsOrAuthRequestDpopNonce)
        updatedAuthorizedRequest to outcome.withSelectedCredentialReusePolicy(selectedCredentialReusePolicy).toPub()
    }

    private fun validateRequestPayload(
        requestPayload: IssuanceRequestPayload,
        authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
    ) {
        if (authorizationDetails.isNotEmpty()) {
            val authorizedIdentifiers = authorizationDetails[requestPayload.credentialConfigurationIdentifier]
            check(!authorizedIdentifiers.isNullOrEmpty()) {
                "No credential identifiers authorized for ${requestPayload.credentialConfigurationIdentifier}"
            }
            require(requestPayload is IssuanceRequestPayload.IdentifierBased) {
                "Authorization detail type of openid_credential require usage of credential identifiers in credential request"
            }
            require(requestPayload.credentialIdentifier in authorizedIdentifiers) {
                "Credential identifier ${requestPayload.credentialIdentifier.value} is not in authorized identifiers $authorizedIdentifiers"
            }
        } else {
            require(requestPayload is IssuanceRequestPayload.ConfigurationBased) {
                "Issuance request payload must be of type ConfigurationBased when no credential identifiers are authorized"
            }
        }
    }

    private suspend fun buildProofs(
        proofsSpecification: ProofsSpecification,
        selectedReusePolicy: EudiReusePolicy?,
        credentialConfigId: CredentialConfigurationIdentifier,
        grant: Grant,
    ): Pair<List<Proof>, Nonce?> {
        val credentialConfiguration = credentialSupportedById(credentialConfigId)
        val proofRequirement = proofsSpecification.ensureCompatibleWith(credentialConfiguration)

        return when (proofsSpecification) {
            is ProofsSpecification.NoProofs -> emptyList<Proof>() to null

            is ProofsSpecification.JwtProofs.WithKeyAttestation -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = listOf(
                    jwtProofWithKeyAttestation(
                        proofRequirement as ProofTypeMeta.Jwt,
                        proofsSpecification,
                        selectedReusePolicy,
                        grant,
                        cNonceAndDPoPNonce?.cnonce,
                    ),
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }

            is ProofsSpecification.JwtProofs.NoKeyAttestation -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = jwtProofsWithoutKeyAttestation(
                    proofRequirement as ProofTypeMeta.Jwt,
                    proofsSpecification,
                    selectedReusePolicy,
                    grant,
                    cNonceAndDPoPNonce?.cnonce,
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }

            is ProofsSpecification.AttestationProof -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = listOf(
                    attestationProof(
                        proofRequirement as ProofTypeMeta.Attestation,
                        proofsSpecification,
                        selectedReusePolicy,
                        cNonceAndDPoPNonce?.cnonce,
                    ),
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }
        }
    }

    private fun ProofsSpecification.ensureCompatibleWith(
        credentialConfiguration: CredentialConfiguration,
    ): ProofTypeMeta? {
        val proofTypesSupported = credentialConfiguration.proofTypesSupported

        return when (this) {
            is ProofsSpecification.NoProofs -> {
                require(proofTypesSupported == ProofTypesSupported.Empty) {
                    "Credential configuration requires proofs."
                }
                null
            }

            is ProofsSpecification.JwtProofs -> {
                val proofRequirement = proofTypesSupported[ProofType.JWT]
                requireNotNull(proofRequirement) {
                    "Credential configuration doesn't support JWT proofs."
                }
                check(proofRequirement is ProofTypeMeta.Jwt)
                val keyAttestationRequirement = proofRequirement.keyAttestationRequirement
                when (this) {
                    is ProofsSpecification.JwtProofs.NoKeyAttestation -> {
                        require(keyAttestationRequirement is KeyAttestationRequirement.NotRequired) {
                            "Credential configuration requires key attestation."
                        }
                    }

                    is ProofsSpecification.JwtProofs.WithKeyAttestation -> {
                        require(keyAttestationRequirement !is KeyAttestationRequirement.NotRequired) {
                            "Credential configuration does not support key attestation."
                        }
                    }
                }
                proofRequirement
            }

            is ProofsSpecification.AttestationProof -> {
                val proofRequirement = proofTypesSupported[ProofType.ATTESTATION]
                requireNotNull(proofRequirement) {
                    "Credential configuration doesn't support attestation proofs."
                }
                check(proofRequirement is ProofTypeMeta.Attestation)
                proofRequirement
            }
        }
    }

    private fun selectCredentialReusePolicy(
        credentialConfiguration: CredentialConfiguration,
    ): EudiReusePolicy? {
        val reusePolicy = credentialConfiguration.credentialMetadata?.credentialReusePolicy
        val issuerEudiReuseTypes = when (reusePolicy) {
            is CredentialReusePolicy.EUDI -> {
                reusePolicy.options.map {
                    when (it) {
                        is EudiReusePolicy.OnceOnly -> EudiReusePolicyType.OnceOnly
                        is EudiReusePolicy.LimitedTime -> EudiReusePolicyType.LimitedTime
                        is EudiReusePolicy.RotatingBatch -> EudiReusePolicyType.RotatingBatch
                        is EudiReusePolicy.PerRelyingParty -> EudiReusePolicyType.PerRelyingParty
                    }
                }.toSet()
            }
            else -> null
        }

        if (config.supportedCredentialReusePolicies is CredentialReusePolicies.Required) {
            requireNotNull(issuerEudiReuseTypes) {
                "Credential reuse policies are required but not supported by issuer"
            }
            require(config.supportedCredentialReusePolicies.policyTypes.intersect(issuerEudiReuseTypes).isNotEmpty()) {
                "None of the required credential reuse policies are supported by issuer"
            }
        }

        return when (reusePolicy) {
            is CredentialReusePolicy.EUDI -> {
                val selectedPolicy = reusePolicy.options.firstOrNull {
                    it.isSupported(config.supportedCredentialReusePolicies)
                }
                requireNotNull(selectedPolicy) {
                    "The configured credential reuse policies cannot support the credential's reuse policy."
                }
            }

            else -> null
        }
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported =
            credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private suspend fun jwtProofWithKeyAttestation(
        proofRequirement: ProofTypeMeta.Jwt,
        proofsSpecification: ProofsSpecification.JwtProofs.WithKeyAttestation,
        selectedReusePolicy: EudiReusePolicy?,
        grant: Grant,
        cNonce: Nonce?,
    ): Proof.Jwt {
        check(proofRequirement.keyAttestationRequirement is KeyAttestationRequirement.Required)

        val proofSigner = proofsSpecification.proofSignerProvider(
            cNonce,
            proofRequirement.keyAttestationRequirement.preferredKeyStorageStatusPeriod,
        )
        val joseAlg = run {
            val javaSigningAlgorithm = proofSigner.javaAlgorithm
            javaSigningAlgorithm.toSupportedJoseAlgorithm(proofRequirement)
        }
        val claims = jwtProofClaims(cNonce = cNonce, grant = grant)
        val jwtProof = proofSigner.use { operation ->
            operation.publicMaterial.ensureKeyAttestationJwtAlgIsSupported(proofRequirement)
            operation.publicMaterial.attestedKeys.assertMatchesBatchIssuanceBatchSize(selectedReusePolicy)
            val signer = KeyAttestationJwtProofSigner(joseAlg, operation, ETSI119472Part3.KEY_ATTESTATION_JWT_PROOF_SIGNING_KEY_INDEX)
            val signedJwt = signer.sign(claims)
            SignedJWT.parse(signedJwt)
        }
        verifyKeyAttestationJwtProofSignature(jwtProof)
        return Proof.Jwt(jwtProof)
    }

    private fun KeyAttestationJWT.ensureKeyAttestationJwtAlgIsSupported(
        spec: ProofTypeMeta,
    ) {
        val attestationJwtAlg = header.algorithm
        ensure(attestationJwtAlg in spec.algorithms()) {
            CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported()
        }
    }

    private suspend fun jwtProofsWithoutKeyAttestation(
        proofRequirement: ProofTypeMeta.Jwt,
        proofsSpecification: ProofsSpecification.JwtProofs.NoKeyAttestation,
        selectedReusePolicy: EudiReusePolicy?,
        grant: Grant,
        cNonce: Nonce?,
    ): List<Proof.Jwt> {
        check(proofRequirement.keyAttestationRequirement is KeyAttestationRequirement.NotRequired)

        val joseAlg = run {
            val javaSigningAlgorithm = proofsSpecification.proofsSigner.javaAlgorithm
            javaSigningAlgorithm.toSupportedJoseAlgorithm(proofRequirement)
        }
        return proofsSpecification.proofsSigner.use { operation ->
            operation.assertMatchesBatchIssuanceBatchSize(selectedReusePolicy)
            val proofsSigner = JwtProofsSigner(joseAlg, operation)
            val claims = jwtProofClaims(cNonce = cNonce, grant = grant)
            proofsSigner.sign(claims).map {
                Proof.Jwt(SignedJWT.parse(it.second))
            }
        }
    }

    private suspend fun attestationProof(
        proofRequirement: ProofTypeMeta.Attestation,
        proofsSpecification: ProofsSpecification.AttestationProof,
        selectedReusePolicy: EudiReusePolicy?,
        cNonce: Nonce?,
    ): Proof.Attestation {
        val keyAttestationJwt = proofsSpecification.attestationProvider(
            cNonce,
            proofRequirement.keyAttestationRequirement.preferredKeyStorageStatusPeriod,
        )
        keyAttestationJwt.ensureKeyAttestationJwtAlgIsSupported(proofRequirement)
        keyAttestationJwt.attestedKeys.assertMatchesBatchIssuanceBatchSize(selectedReusePolicy)
        return Proof.Attestation(keyAttestationJwt)
    }

    private fun BatchSignOperation<JwtBindingKey>.assertMatchesBatchIssuanceBatchSize(
        selectedReusePolicy: EudiReusePolicy?,
    ) = operations.size.assertMatchesBatchIssuanceBatchSize(selectedReusePolicy)

    private fun List<JWK>.assertMatchesBatchIssuanceBatchSize(
        selectedReusePolicy: EudiReusePolicy?,
    ) = size.assertMatchesBatchIssuanceBatchSize(selectedReusePolicy)

    private fun Int.assertMatchesBatchIssuanceBatchSize(
        selectedReusePolicy: EudiReusePolicy?,
    ) = when (this) {
        0 -> error("At least one PopSigner is required in Authorized.ProofRequired")
        1 -> Unit
        else -> {
            if (selectedReusePolicy != null) {
                when (selectedReusePolicy) {
                    is EudiReusePolicy.LimitedTime ->
                        throw CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance()

                    else -> {
                        val policyBatchSize = checkNotNull(selectedReusePolicy.batchSize) {
                            "Batch reuse policy ${selectedReusePolicy::class} with null batch size"
                        }
                        ensure(this <= policyBatchSize) {
                            CredentialIssuanceError.IssuerBatchSizeLimitExceeded(policyBatchSize)
                        }
                    }
                }
            } else {
                when (batchCredentialIssuance) {
                    BatchCredentialIssuance.NotSupported -> throw CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance()
                    is BatchCredentialIssuance.Supported -> {
                        val maxBatchSize = batchCredentialIssuance.batchSize
                        ensure(this <= maxBatchSize) {
                            CredentialIssuanceError.IssuerBatchSizeLimitExceeded(maxBatchSize)
                        }
                    }
                }
            }
        }
    }

    private fun String.toSupportedJoseAlgorithm(spec: ProofTypeMeta.Jwt): JWSAlgorithm =
        spec.let {
            val joseSigningAlgorithm = this.toJoseAlg()
            val proofTypeSigningAlgorithmsSupported = spec.algorithms
            ensure(joseSigningAlgorithm in proofTypeSigningAlgorithmsSupported) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported()
            }
            joseSigningAlgorithm
        }

    private suspend fun cNonce(): CNonceAndDPoPNonce? = nonceEndpointClient?.getNonce()?.getOrThrow()

    private fun jwtProofClaims(
        cNonce: Nonce?,
        grant: Grant,
    ): JwtProofClaims {
        fun iss(clientAuthentication: ClientAuthentication, grant: Grant): ClientId? {
            val useIss = when (grant) {
                Grant.AuthorizationCode -> true
                Grant.PreAuthorizedCodeGrant -> when (clientAuthentication) {
                    is ClientAuthentication.AttestationBased -> true
                    is ClientAuthentication.None -> false
                }
            }
            return clientAuthentication.id.takeIf { useIss }
        }

        return JwtProofClaims(
            audience = credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier.toString(),
            issuedAt = Instant.now(),
            issuer = iss(config.clientAuthentication, grant),
            nonce = cNonce?.value,
        )
    }

    private fun verifyKeyAttestationJwtProofSignature(jwtProof: SignedJWT) {
        val keyAttestationJwt = jwtProof.header.getCustomParam("key_attestation") as? String
            ?: throw IllegalArgumentException("Missing 'key_attestation' in JWT header")
        val keyAttestation = KeyAttestationJWT(keyAttestationJwt)
        val attestedKeys = keyAttestation.attestedKeys
        val signatureVerified = try {
            val signingKey = attestedKeys[ETSI119472Part3.KEY_ATTESTATION_JWT_PROOF_SIGNING_KEY_INDEX].toECKey()
            val verifier = ECDSAVerifier(signingKey)
            jwtProof.verify(verifier)
        } catch (_: Exception) {
            false
        }
        require(signatureVerified) {
            "Signed JWT is not signed by the first attested key in key_attestation."
        }
    }

    private fun buildRequest(
        requestPayload: IssuanceRequestPayload,
        proofs: List<Proof>,
        authorizationDetails: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>,
    ): CredentialIssuanceRequest = when (requestPayload) {
        is IssuanceRequestPayload.ConfigurationBased -> {
            CredentialIssuanceRequest.byCredentialConfigurationId(
                requestPayload.credentialConfigurationIdentifier,
                proofs,
                exchangeEncryptionSpecification,
            )
        }

        is IssuanceRequestPayload.IdentifierBased -> {
            requestPayload.ensureAuthorized(authorizationDetails)
            CredentialIssuanceRequest.byCredentialId(
                requestPayload.credentialIdentifier,
                proofs,
                exchangeEncryptionSpecification,
            )
        }
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

internal sealed interface SubmissionOutcomeInternal {

    data class Success(
        val credentials: List<IssuedCredential>,
        val notificationId: NotificationId?,
        val selectedCredentialReusePolicy: EudiReusePolicy? = null,
    ) : SubmissionOutcomeInternal

    data class Deferred(
        val transactionId: TransactionId,
        val interval: Duration,
    ) : SubmissionOutcomeInternal {
        init {
            require(interval.isPositive()) { "interval must be positive" }
        }
    }

    data class Failed(
        val error: CredentialIssuanceError,
    ) : SubmissionOutcomeInternal

    fun toPub(): SubmissionOutcome =
        when (this) {
            is Success -> SubmissionOutcome.Success(credentials, notificationId, selectedCredentialReusePolicy)
            is Deferred -> SubmissionOutcome.Deferred(transactionId, interval)
            is Failed -> SubmissionOutcome.Failed(error)
        }

    fun withSelectedCredentialReusePolicy(
        selectedCredentialReusePolicy: EudiReusePolicy?,
    ): SubmissionOutcomeInternal =
        when (this) {
            is Success -> copy(selectedCredentialReusePolicy = selectedCredentialReusePolicy)
            is Deferred, is Failed -> this
        }
}
