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

internal fun responseEncryptionSpec(
    credentialOffer: CredentialOffer,
    config: OpenId4VCIConfig,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
): Result<IssuanceResponseEncryptionSpec?> = runCatching {
    fun IssuanceResponseEncryptionSpec.validate(
        supportedResponseEncryptionParameters: SupportedResponseEncryptionParameters,
    ) {
        val algorithm = algorithm
        requireNotNull(algorithm) {
            ResponseEncryptionKeyDoesNotSpecifyAlgorithm()
        }
        ensure(algorithm in supportedResponseEncryptionParameters.algorithms) {
            ResponseEncryptionAlgorithmNotSupportedByIssuer()
        }
        ensure(encryptionMethod in supportedResponseEncryptionParameters.encryptionMethods) {
            ResponseEncryptionMethodNotSupportedByIssuer()
        }
        compressionAlgorithm?.let {
            ensure(supportedResponseEncryptionParameters.payloadCompression is PayloadCompression.Supported) {
                IssuerDoesNotSupportEncryptedPayloadCompression()
            }
            ensure(it in supportedResponseEncryptionParameters.payloadCompression.algorithms) {
                IssuerDoesNotSupportEncryptedPayloadCompressionAlgorithm()
            }
        }
    }

    when (val encryption = credentialOffer.credentialIssuerMetadata.credentialResponseEncryption) {
        CredentialResponseEncryption.NotSupported ->
            // Issuance server does not support Credential Response encryption.
            // In case Wallet requires Credential Response encryption, fail.
            when (config.credentialResponseEncryptionPolicy) {
                CredentialResponseEncryptionPolicy.SUPPORTED -> null
                CredentialResponseEncryptionPolicy.REQUIRED -> throw ResponseEncryptionRequiredByWalletButNotSupportedByIssuer()
            }

        is CredentialResponseEncryption.SupportedNotRequired -> {
            // Issuance server supports but does not require Credential Response encryption.
            // Fail in case Wallet requires Credential Response encryption but no crypto material can be generated,
            // or in case algorithm/method supported by Wallet is not supported by issuance server.
            val supportedResponseEncryptionParameters = encryption.encryptionParameters
            val maybeSpec = runCatching {
                responseEncryptionSpecFactory(
                    supportedResponseEncryptionParameters,
                    config.keyGenerationConfig,
                    config.supportedCompressionAlgorithms,
                )?.apply { validate(supportedResponseEncryptionParameters) }
            }.getOrNull()

            when (config.credentialResponseEncryptionPolicy) {
                CredentialResponseEncryptionPolicy.SUPPORTED -> maybeSpec

                CredentialResponseEncryptionPolicy.REQUIRED -> {
                    ensureNotNull(maybeSpec) {
                        WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated()
                    }
                }
            }
        }

        is CredentialResponseEncryption.Required -> {
            // Issuance server requires Credential Response encryption.
            // Fail in case Wallet does not support Credential Response encryption or,
            // algorithms/methods supported by Wallet are not supported by issuance server.
            val supportedResponseEncryptionParameters = encryption.encryptionParameters
            val maybeSpec = responseEncryptionSpecFactory(
                supportedResponseEncryptionParameters,
                config.keyGenerationConfig,
                config.supportedCompressionAlgorithms,
            )?.apply { validate(supportedResponseEncryptionParameters) }
            ensureNotNull(maybeSpec) { IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided() }
        }
    }
}
