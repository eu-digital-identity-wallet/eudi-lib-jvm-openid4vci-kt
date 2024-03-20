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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequest

internal class RequestIssuanceImpl(
    private val credentialOffer: CredentialOffer,
    private val issuerMetadata: CredentialIssuerMetadata,
    private val config: OpenId4VCIConfig,
    private val issuanceServerClient: IssuanceServerClient,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
) : RequestIssuance {

    private val responseEncryptionSpec: IssuanceResponseEncryptionSpec? by lazy {
        fun IssuanceResponseEncryptionSpec.validate(
            algorithmsSupported: List<JWEAlgorithm>,
            encryptionMethodsSupported: List<EncryptionMethod>,
        ) {
            ensure(algorithm in algorithmsSupported) {
                CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer
            }
            ensure(encryptionMethod in encryptionMethodsSupported) {
                CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer
            }
        }

        when (val encryption = issuerMetadata.credentialResponseEncryption) {
            CredentialResponseEncryption.NotSupported -> null

            is CredentialResponseEncryption.SupportedNotRequired ->
                responseEncryptionSpecFactory(encryption, config.keyGenerationConfig)?.apply {
                    validate(encryption.algorithmsSupported, encryption.encryptionMethodsSupported)
                }

            is CredentialResponseEncryption.Required ->
                responseEncryptionSpecFactory(encryption, config.keyGenerationConfig)?.apply {
                    validate(encryption.algorithmsSupported, encryption.encryptionMethodsSupported)
                } ?: throw IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
        }
    }

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
            singleRequest(requestPayload, proofFactory(proofSigner, cNonce), credentialIdentifiers)
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
                singleRequest(requestPayload, proofFactory(proofSigner, cNonce), credentialIdentifiers)
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
        requestPayload: IssuanceRequestPayload,
        proofFactory: ProofFactory?,
        credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
    ): CredentialIssuanceRequest.SingleRequest =
        when (requestPayload) {
            is IssuanceRequestPayload.ConfigurationBased -> {
                formatBasedRequest(requestPayload.credentialConfigurationIdentifier, requestPayload.claimSet, proofFactory)
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
    ): AuthorizedRequest.ProofRequired = AuthorizedRequest.ProofRequired(accessToken, cNonce, credentialIdentifiers)

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
}

private fun submitRequestFromError(error: Throwable): SubmittedRequest.Errored? = when (error) {
    is CredentialIssuanceError.InvalidProof ->
        SubmittedRequest.InvalidProof(CNonce(error.cNonce, error.cNonceExpiresIn))

    is CredentialIssuanceError -> SubmittedRequest.Failed(error)
    else -> null
}
