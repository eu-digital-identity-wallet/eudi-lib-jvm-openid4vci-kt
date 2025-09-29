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
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
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
        if (nonceEndpoint != null && nonceEndpointClient == null) {
            throw IllegalStateException("A nonce endpoint client needs to be configured if issuer advertises a nonce endpoint")
        }
        if (nonceEndpoint == null && nonceEndpointClient != null) {
            throw IllegalStateException("A nonce endpoint client is configured although issuer does not advertises a nonce endpoint")
        }
    }

    override suspend fun AuthorizedRequest.request(
        requestPayload: IssuanceRequestPayload,
        proofsSpecification: ProofsSpecification,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        val (proofs, proofsDpopNonce) = buildProofs(proofsSpecification, requestPayload.credentialConfigurationIdentifier, grant)
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
        updatedAuthorizedRequest to outcome.toPub()
    }

    private suspend fun buildProofs(
        proofsSpecification: ProofsSpecification,
        credentialConfigId: CredentialConfigurationIdentifier,
        grant: Grant,
    ): Pair<List<Proof>, Nonce?> {
        proofsSpecification.ensureCompatibleWith(credentialConfigId)

        return when (proofsSpecification) {
            is ProofsSpecification.NoProofs -> emptyList<Proof>() to null

            is ProofsSpecification.JwtProofs.WithKeyAttestation -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = listOf(
                    jwtProofWithKeyAttestation(
                        proofsSpecification,
                        credentialConfigId,
                        grant,
                        cNonceAndDPoPNonce?.cnonce,
                    ),
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }

            is ProofsSpecification.JwtProofs.NoKeyAttestation -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = jwtProofsWithoutKeyAttestation(
                    proofsSpecification,
                    credentialConfigId,
                    grant,
                    cNonceAndDPoPNonce?.cnonce,
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }

            is ProofsSpecification.AttestationProof -> {
                val cNonceAndDPoPNonce = cNonce()
                val proofs = listOf(
                    attestationProof(
                        proofsSpecification,
                        credentialConfigId,
                        cNonceAndDPoPNonce?.cnonce,
                    ),
                )
                proofs to cNonceAndDPoPNonce?.dpopNonce
            }
        }
    }

    private fun ProofsSpecification.ensureCompatibleWith(credentialConfigId: CredentialConfigurationIdentifier) {
        val credentialConfiguration = credentialSupportedById(credentialConfigId)
        val proofTypesSupported = credentialConfiguration.proofTypesSupported

        when (this) {
            is ProofsSpecification.NoProofs -> {
                require(proofTypesSupported == ProofTypesSupported.Empty) {
                    "Credential configuration requires proofs."
                }
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
            }

            is ProofsSpecification.AttestationProof -> {
                requireNotNull(proofTypesSupported[ProofType.ATTESTATION]) {
                    "Credential configuration doesn't support attestation proofs."
                }
            }
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
        proofsSpecification: ProofsSpecification.JwtProofs.WithKeyAttestation,
        credentialConfigId: CredentialConfigurationIdentifier,
        grant: Grant,
        cNonce: Nonce?,
    ): Proof.Jwt {
        val (proofSignerProvider, keyIndex) = proofsSpecification
        val proofSigner = proofSignerProvider(cNonce)
        val joseAlg = run {
            val javaSigningAlgorithm = proofSigner.javaAlgorithm
            javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)
        }
        val claims = jwtProofClaims(cNonce = cNonce, grant = grant)
        val jwtProof = proofSigner.use { operation ->
            operation.publicMaterial.ensureKeyAttestationJwtAlgIsSupported(credentialConfigId, ProofType.JWT)
            val signer = KeyAttestationJwtProofSigner(joseAlg, operation, keyIndex)
            val signedJwt = signer.sign(claims)
            SignedJWT.parse(signedJwt)
        }
        verifyKeyAttestationJwtProofSignature(jwtProof)
        return Proof.Jwt(jwtProof)
    }

    private fun KeyAttestationJWT.ensureKeyAttestationJwtAlgIsSupported(
        credentialConfigId: CredentialConfigurationIdentifier,
        proofType: ProofType,
    ) {
        val attestationJwtAlg = SignedJWT.parse(value).header.algorithm
        val proofTypesSupported = credentialSupportedById(credentialConfigId).proofTypesSupported
        val spec = proofTypesSupported.values.firstOrNull { it.type() == proofType }
        ensure(spec != null && attestationJwtAlg in spec.algorithms()) {
            CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported()
        }
    }

    private suspend fun jwtProofsWithoutKeyAttestation(
        proofsSpecification: ProofsSpecification.JwtProofs.NoKeyAttestation,
        credentialConfigId: CredentialConfigurationIdentifier,
        grant: Grant,
        cNonce: Nonce?,
    ): List<Proof.Jwt> {
        val joseAlg = run {
            val javaSigningAlgorithm = proofsSpecification.proofsSigner.javaAlgorithm
            javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)
        }
        return proofsSpecification.proofsSigner.use { operation ->
            operation.assertMatchesBatchIssuanceBatchSize()
            val proofsSigner = JwtProofsSigner(joseAlg, operation)
            val claims = jwtProofClaims(cNonce = cNonce, grant = grant)
            proofsSigner.sign(claims).map {
                Proof.Jwt(SignedJWT.parse(it.second))
            }
        }
    }

    private suspend fun attestationProof(
        proofsSpecification: ProofsSpecification.AttestationProof,
        credentialConfigId: CredentialConfigurationIdentifier,
        cNonce: Nonce?,
    ): Proof.Attestation {
        val keyAttestationJwt = proofsSpecification.attestationProvider(cNonce)
        keyAttestationJwt.ensureKeyAttestationJwtAlgIsSupported(credentialConfigId, ProofType.ATTESTATION)
        return Proof.Attestation(keyAttestationJwt)
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

    private suspend fun cNonce(): CNonceAndDPoPNonce? = nonceEndpointClient?.getNonce()?.getOrThrow()

    private fun jwtProofClaims(
        cNonce: Nonce?,
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

    private fun verifyKeyAttestationJwtProofSignature(jwtProof: SignedJWT) {
        val keyAttestationJwt = jwtProof.header.getCustomParam("key_attestation") as? String
            ?: throw IllegalArgumentException("Missing 'key_attestation' in JWT header")
        val keyAttestation = KeyAttestationJWT(keyAttestationJwt)
        val attestedKeys = keyAttestation.attestedKeys
        val jwk = attestedKeys.firstOrNull { jwk: JWK ->
            try {
                val verifier = when (jwk) {
                    is RSAKey -> RSASSAVerifier(jwk)
                    is ECKey -> ECDSAVerifier(jwk)
                    else -> null
                }
                verifier != null && jwtProof.verify(verifier)
            } catch (_: Exception) {
                false
            }
        }
        requireNotNull(jwk) {
            "Signed JWT is not signed by any of the attested keys in key_attestation."
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
            is Success -> SubmissionOutcome.Success(credentials, notificationId)
            is Deferred -> SubmissionOutcome.Deferred(transactionId, interval)
            is Failed -> SubmissionOutcome.Failed(error)
        }
}
