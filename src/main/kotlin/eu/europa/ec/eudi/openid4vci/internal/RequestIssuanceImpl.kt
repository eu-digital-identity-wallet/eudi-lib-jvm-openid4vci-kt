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
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialEndpointClient
import eu.europa.ec.eudi.openid4vci.internal.http.NonceEndpointClient
import java.time.Instant

private sealed interface NonceRequirement {

    data object Required : NonceRequirement

    data object NotRequired : NonceRequirement
}

private data class ProofRequirements(
    val nonceRequirement: NonceRequirement,
    val keyAttestationRequirement: KeyAttestationRequirement,
)

private sealed interface CredentialProofsRequirement {

    data object ProofNotRequired : CredentialProofsRequirement

    data class ProofRequired(
        val proofTypeRequirements: Map<ProofType, ProofRequirements>,
    ) : CredentialProofsRequirement
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
        proofsSpecification: ProofsSpecification,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = runCatching {
        val credentialConfigId = requestPayload.credentialConfigurationIdentifier
        val proofsRequirement = credentialConfigId.proofsRequirement()

        // Place the request
        val (outcome, newResourceServerDpopNonce) = placeIssuanceRequest(accessToken, resourceServerDpopNonce) {
            proofsSpecification.ensureCompatibleWith(proofsRequirement)

            when (proofsSpecification) {
                is ProofsSpecification.NoProofs -> buildRequest(requestPayload, null, credentialIdentifiers.orEmpty())
                is ProofsSpecification.JwtProofs.WithKeyAttestation -> proofsSpecification.proofSigner.use { signOp ->
                    val proofsFactory = keyAttestationJwtProofFactoryFrom(
                        signOp,
                        proofsSpecification.keyIndex,
                        proofsSpecification.proofSigner.javaAlgorithm,
                        credentialConfigId,
                        proofsRequirement,
                    )
                    buildRequest(requestPayload, proofsFactory, credentialIdentifiers.orEmpty())
                }

                is ProofsSpecification.JwtProofs.NoKeyAttestation -> proofsSpecification.proofsSigner.use { signOps ->
                    val proofsFactory = jwtProofsFactoryFrom(
                        signOps,
                        proofsSpecification.proofsSigner.javaAlgorithm,
                        credentialConfigId,
                        proofsRequirement,
                    )
                    buildRequest(requestPayload, proofsFactory, credentialIdentifiers.orEmpty())
                }

                is ProofsSpecification.AttestationProof -> {
                    val proofsFactory: ProofsFactory = {
                        listOf(Proof.Attestation(proofsSpecification.attestation))
                    }
                    buildRequest(requestPayload, proofsFactory, credentialIdentifiers.orEmpty())
                }
            }
        }

        // Update state (maybe) with new Dpop Nonce from resource server
        val updatedAuthorizedRequest = this.withResourceServerDpopNonce(newResourceServerDpopNonce)
        updatedAuthorizedRequest to outcome.toPub()
    }

    private fun ProofsSpecification.ensureCompatibleWith(proofsRequirement: CredentialProofsRequirement) =
        when (this) {
            is ProofsSpecification.NoProofs -> {
                require(proofsRequirement is CredentialProofsRequirement.ProofNotRequired) {
                    "No proofs are provided, but credential configuration requires proofs"
                }
            }
            is ProofsSpecification.JwtProofs -> {
                require(proofsRequirement is CredentialProofsRequirement.ProofRequired)
                requireNotNull(proofsRequirement.proofTypeRequirements[ProofType.JWT]) {
                    "JWT proofs are provided, but credential configuration does not support JWT proofs"
                }
                val (_, keyAttestationReq) = proofsRequirement.proofTypeRequirements[ProofType.JWT]!!

                when (this) {
                    is ProofsSpecification.JwtProofs.NoKeyAttestation -> {
                        require(keyAttestationReq is KeyAttestationRequirement.NotRequired) {
                            "JWT proof without key attestation is provided, but credential configuration requires key attestation"
                        }
                    }
                    is ProofsSpecification.JwtProofs.WithKeyAttestation -> {
                        require(keyAttestationReq !is KeyAttestationRequirement.NotRequired) {
                            "JWT proof with key attestation is provided, " +
                                "but credential configuration does not support key attestation"
                        }
                    }
                }
            }
            is ProofsSpecification.AttestationProof -> {
                require(proofsRequirement is CredentialProofsRequirement.ProofRequired)
                val requirements = proofsRequirement.proofTypeRequirements[ProofType.ATTESTATION]
                requireNotNull(requirements) {
                    "Attestation proof is provided, but credential configuration does not support attestation proofs"
                }
                require(requirements.keyAttestationRequirement !is KeyAttestationRequirement.NotRequired) {
                    "Problematic attestation proof key requirement. Issuer requires no key attestation for proof of type 'attestation'"
                }
            }
        }

    private fun CredentialConfigurationIdentifier.proofsRequirement(): CredentialProofsRequirement {
        val credentialIssuerMetadata = credentialOffer.credentialIssuerMetadata
        val credentialConfiguration = credentialSupportedById(this)
        return when {
            credentialConfiguration.proofTypesSupported.values.isEmpty() -> CredentialProofsRequirement.ProofNotRequired
            else -> CredentialProofsRequirement.ProofRequired(
                credentialConfiguration.proofTypesSupported.values.associate { proofTypeMeta ->
                    val proofType = proofTypeMeta.type() ?: error("Unsupported proof type: $proofTypeMeta")
                    val keyAttestationRequirement = keyAttestationProofsRequirement(proofTypeMeta)
                    val nonceRequirement = when (credentialIssuerMetadata.nonceEndpoint) {
                        null -> NonceRequirement.NotRequired
                        else -> NonceRequirement.Required
                    }
                    proofType to ProofRequirements(
                        nonceRequirement = nonceRequirement,
                        keyAttestationRequirement = keyAttestationRequirement,
                    )
                },
            )
        }
    }

    private fun CredentialConfigurationIdentifier.keyAttestationProofsRequirement(proofType: ProofTypeMeta): KeyAttestationRequirement {
        val credentialConfiguration = credentialSupportedById(this)
        val spec = credentialConfiguration.proofTypesSupported.values.filterIsInstance(proofType::class.java).firstOrNull()
        return when (spec) {
            null -> KeyAttestationRequirement.NotRequired
            is ProofTypeMeta.Jwt -> spec.keyAttestationRequirement
            is ProofTypeMeta.Attestation -> spec.keyAttestationRequirement
            is ProofTypeMeta.LdpVp,
            is ProofTypeMeta.Unsupported,
            -> KeyAttestationRequirement.NotRequired
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
        keyAttestationSigner: SignOperation<KeyAttestationJWT>,
        keyIndex: Int,
        javaSigningAlgorithm: String,
        credentialConfigId: CredentialConfigurationIdentifier,
        proofRequirements: CredentialProofsRequirement,
    ): ProofsFactory {
        require(proofRequirements is CredentialProofsRequirement.ProofRequired)
        val jwtProofType = checkNotNull(proofRequirements.proofTypeRequirements[ProofType.JWT])
        val joseAlg = javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)

        val cNonce = jwtProofType.cNonce()
        return keyAttestationProofsFactory(
            KeyAttestationJwtProofSigner(joseAlg, keyAttestationSigner, keyIndex),
            cNonce,
            grant,
        )
    }

    private suspend fun AuthorizedRequest.jwtProofsFactoryFrom(
        proofsSigner: BatchSignOperation<JwtBindingKey>,
        javaSigningAlgorithm: String,
        credentialConfigId: CredentialConfigurationIdentifier,
        proofRequirements: CredentialProofsRequirement,
    ): ProofsFactory {
        require(proofRequirements is CredentialProofsRequirement.ProofRequired)
        proofsSigner.assertMatchesBatchIssuanceBatchSize()
        val jwtProofType = checkNotNull(proofRequirements.proofTypeRequirements[ProofType.JWT])
        val joseAlg = javaSigningAlgorithm.toSupportedJoseAlgorithm(credentialConfigId)

        val cNonce = jwtProofType.cNonce()
        val proofsSigner = JwtProofsSigner(joseAlg, proofsSigner)
        return proofsFactory(proofsSigner, cNonce, grant)
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

    private suspend fun ProofRequirements.cNonce(): CNonce? =
        when (nonceRequirement) {
            NonceRequirement.NotRequired -> null
            NonceRequirement.Required -> {
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

        val jwtProof = SignedJWT.parse(signedJwt)
        verifyKeyAttestationJwtProofSignature(jwtProof)

        listOf(Proof.Jwt(jwtProof))
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
        is Proof.Attestation -> ProofType.ATTESTATION
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
