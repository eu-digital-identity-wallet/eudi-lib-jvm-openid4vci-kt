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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.*
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest

internal class RequestIssuanceImpl private constructor(
    private val credentialOffer: CredentialOffer,
    private val issuanceServerClient: IssuanceServerClient,
    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
) : RequestIssuance {
    override suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        requestPayload: IssuanceRequestPayload,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            singleRequest(requestPayload, null, credentialIdentifiers)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        requestPayload: IssuanceRequestPayload,
        proofSigner: ProofSigner,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            singleRequest(requestPayload, proofFactory(proofSigner, cNonce, clientId), credentialIdentifiers)
        }
    }

    override suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<IssuanceRequestPayload>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map {
                singleRequest(it, null, credentialIdentifiers)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests)
        }
    }

    override suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Pair<IssuanceRequestPayload, ProofSigner>>,
    ): Result<SubmittedRequest> = runCatching {
        placeIssuanceRequest(accessToken) {
            val credentialRequests = credentialsMetadata.map { (requestPayload, proofSigner) ->
                singleRequest(requestPayload, proofFactory(proofSigner, cNonce, clientId), credentialIdentifiers)
            }
            CredentialIssuanceRequest.BatchRequest(credentialRequests)
        }
    }

    private fun credentialSupportedById(credentialId: CredentialConfigurationIdentifier): CredentialConfiguration {
        val credentialSupported = credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported[credentialId]
        return requireNotNull(credentialSupported) {
            "$credentialId was not found within issuer metadata"
        }
    }

    private fun proofFactory(proofSigner: ProofSigner, cNonce: CNonce, clientId: ClientId): ProofFactory = { credentialSupported ->
        ProofBuilder.ofType(ProofType.JWT) {
            iss(clientId)
            aud(credentialOffer.credentialIssuerMetadata.credentialIssuerIdentifier.toString())
            publicKey(proofSigner.getBindingKey())
            credentialSpec(credentialSupported)
            nonce(cNonce.value)
            build(proofSigner)
        }
    }

    private fun singleRequest(
        requestPayload: IssuanceRequestPayload,
        proofFactory: ProofFactory?,
        credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
    ): CredentialIssuanceRequest.SingleRequest =
        when (requestPayload) {
            is IssuanceRequestPayload.ConfigurationBased -> {
                formatBasedRequest(
                    requestPayload.credentialConfigurationIdentifier,
                    requestPayload.claimSet,
                    proofFactory,
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
                identifierBasedRequest(credentialConfigurationId, credentialId, proofFactory)
            }
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
        credentialConfigurationId: CredentialConfigurationIdentifier,
        credentialId: CredentialIdentifier,
        proofFactory: ProofFactory?,
    ): CredentialIssuanceRequest.IdentifierBased {
        require(credentialOffer.credentialConfigurationIdentifiers.contains(credentialConfigurationId)) {
            "The requested credential is not authorized for issuance"
        }
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
        clientId: ClientId,
    ): AuthorizedRequest.ProofRequired = AuthorizedRequest.ProofRequired(accessToken, refreshToken, cNonce, clientId, credentialIdentifiers)

    private suspend fun placeIssuanceRequest(
        token: AccessToken,
        issuanceRequestSupplier: () -> CredentialIssuanceRequest,
    ): SubmittedRequest {
        fun handleIssuanceFailure(error: Throwable): SubmittedRequest.Errored =
            submitRequestFromError(error) ?: throw error
        return when (val credentialRequest = issuanceRequestSupplier()) {
            is CredentialIssuanceRequest.SingleRequest -> {
                issuanceServerClient.placeIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }

            is CredentialIssuanceRequest.BatchRequest -> {
                issuanceServerClient.placeBatchIssuanceRequest(token, credentialRequest).fold(
                    onSuccess = { SubmittedRequest.Success(it.credentials, it.cNonce) },
                    onFailure = { handleIssuanceFailure(it) },
                )
            }
        }
    }

    companion object {
        operator fun invoke(
            credentialOffer: CredentialOffer,
            config: OpenId4VCIConfig,
            issuanceServerClient: IssuanceServerClient,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
        ): Result<RequestIssuanceImpl> = runCatching {
            val responseEncryptionSpec =
                responseEncryptionSpec(credentialOffer, config, responseEncryptionSpecFactory).getOrThrow()
            RequestIssuanceImpl(credentialOffer, issuanceServerClient, responseEncryptionSpec)
        }
    }
}

private fun responseEncryptionSpec(
    credentialOffer: CredentialOffer,
    config: OpenId4VCIConfig,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
): Result<IssuanceResponseEncryptionSpec?> = runCatching {
    fun IssuanceResponseEncryptionSpec.validate(
        supportedAlgorithmsAndMethods: SupportedEncryptionAlgorithmsAndMethods,
    ) {
        ensure(algorithm in supportedAlgorithmsAndMethods.algorithms) {
            ResponseEncryptionAlgorithmNotSupportedByIssuer
        }
        ensure(encryptionMethod in supportedAlgorithmsAndMethods.encryptionMethods) {
            ResponseEncryptionMethodNotSupportedByIssuer
        }
    }

    when (val encryption = credentialOffer.credentialIssuerMetadata.credentialResponseEncryption) {
        CredentialResponseEncryption.NotSupported ->
            // Issuance server does not support Credential Response encryption.
            // In case Wallet requires Credential Response encryption, fail.
            when (config.credentialResponseEncryptionPolicy) {
                CredentialResponseEncryptionPolicy.SUPPORTED -> null
                CredentialResponseEncryptionPolicy.REQUIRED -> throw ResponseEncryptionRequiredByWalletButNotSupportedByIssuer
            }

        is CredentialResponseEncryption.SupportedNotRequired -> {
            // Issuance server supports but does not require Credential Response encryption.
            // Fail in case Wallet requires Credential Response encryption but no crypto material can be generated,
            // or in case algorithm/method supported by Wallet is not supported by issuance server.
            val supportedAlgorithmsAndMethods = encryption.encryptionAlgorithmsAndMethods
            val maybeSpec = runCatching {
                responseEncryptionSpecFactory(supportedAlgorithmsAndMethods, config.keyGenerationConfig)
                    ?.apply {
                        validate(supportedAlgorithmsAndMethods)
                    }
            }.getOrNull()

            when (config.credentialResponseEncryptionPolicy) {
                CredentialResponseEncryptionPolicy.SUPPORTED -> maybeSpec

                CredentialResponseEncryptionPolicy.REQUIRED -> {
                    ensureNotNull(maybeSpec) {
                        WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated
                    }
                }
            }
        }

        is CredentialResponseEncryption.Required -> {
            // Issuance server requires Credential Response encryption.
            // Fail in case Wallet does not support Credential Response encryption or,
            // algorithms/methods supported by Wallet are not supported by issuance server.
            val supportedAlgorithmsAndMethods = encryption.encryptionAlgorithmsAndMethods
            val maybeSpec = responseEncryptionSpecFactory(supportedAlgorithmsAndMethods, config.keyGenerationConfig)
                ?.apply {
                    validate(supportedAlgorithmsAndMethods)
                }
            ensureNotNull(maybeSpec) { IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided }
        }
    }
}

private fun submitRequestFromError(error: Throwable): SubmittedRequest.Errored? = when (error) {
    is CredentialIssuanceError.InvalidProof ->
        SubmittedRequest.InvalidProof(CNonce(error.cNonce, error.cNonceExpiresIn))

    is CredentialIssuanceError -> SubmittedRequest.Failed(error)
    else -> null
}
