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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.RequestEncryptionError.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.*

/**
 * Constructs encryption specifications used for issuance requests and responses, based on the provided
 * credential offer, configuration, and encryption specification factories.
 *
 * @param encryptionSupportConfig The configuration object containing wallet-specific properties and policies for encryption.
 * @param credentialRequestEncryption Issuer metadata about its capability to encrypt issuance requests.
 * @param credentialResponseEncryption Issuer metadata about its capability to encrypt issuance responses.
 * @param responseEncryptionSpecFactory A factory for creating the response encryption specification based on supported parameters.
 * @param requestEncryptionSpecFactory A factory for creating the request encryption specification needed for secure communication.
 * @return A Result object containing the `IssuanceEncryptionSpecs` that hold the encryption specifications
 *         for request and response, or an error if encryption specification creation fails.
 */
internal fun issuanceEncryptionSpecs(
    encryptionSupportConfig: EncryptionSupportConfig,
    credentialRequestEncryption: CredentialRequestEncryption,
    credentialResponseEncryption: CredentialResponseEncryption,
    requestEncryptionSpecFactory: RequestEncryptionSpecFactory,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
): Result<IssuanceEncryptionSpecs> = runCatching {
    val requestEncryptionSpec = requestEncryptionSpec(
        credentialRequestEncryption,
        encryptionSupportConfig,
        requestEncryptionSpecFactory,
    ).getOrThrow()
    val responseEncryptionSpec = responseEncryptionSpec(
        credentialResponseEncryption,
        encryptionSupportConfig,
        responseEncryptionSpecFactory,
    ).getOrThrow()

    IssuanceEncryptionSpecs(requestEncryptionSpec = requestEncryptionSpec, responseEncryptionSpec = responseEncryptionSpec)
}

/**
 * Generates and validates the encryption specifications for the credential response based on
 * the supported credential response encryption methods of the issuer, wallet's configuration,
 * and the required encryption parameters.
 *
 * @param issuerSupportedCredentialResponseEncryption The credential response encryption as declared by the issuer.
 * @param walletEncryptionSupportConfig The configuration object that provides wallet-specific details including encryption policies and rules.
 * @param responseEncryptionSpecFactory A factory function to generate encryption specifications based on supported parameters and wallet configuration.
 * @return A Result containing the generated EncryptionSpec if encryption is supported or required, or null if optional and no encryption is generated.
 */
private fun responseEncryptionSpec(
    issuerSupportedCredentialResponseEncryption: CredentialResponseEncryption,
    walletEncryptionSupportConfig: EncryptionSupportConfig,
    responseEncryptionSpecFactory: ResponseEncryptionSpecFactory,
): Result<EncryptionSpec?> = runCatching {
    fun EncryptionSpec.validate(
        issuerSupportedResponseEncryptionParameters: SupportedResponseEncryptionParameters,
    ) {
        ensure(algorithm in issuerSupportedResponseEncryptionParameters.algorithms) {
            ResponseEncryptionAlgorithmNotSupportedByIssuer()
        }
        ensure(encryptionMethod in issuerSupportedResponseEncryptionParameters.encryptionMethods) {
            ResponseEncryptionMethodNotSupportedByIssuer()
        }
        compressionAlgorithm?.let {
            ensure(issuerSupportedResponseEncryptionParameters.payloadCompression is PayloadCompression.Supported) {
                IssuerDoesNotSupportEncryptedPayloadCompression()
            }
            ensure(it in issuerSupportedResponseEncryptionParameters.payloadCompression.algorithms) {
                IssuerDoesNotSupportEncryptedPayloadCompressionAlgorithm()
            }
        }
    }

    when (val encryption = issuerSupportedCredentialResponseEncryption) {
        CredentialResponseEncryption.NotSupported ->
            // Issuance server does not support Credential Response encryption.
            // In case Wallet requires Credential Response encryption, fail.
            when (walletEncryptionSupportConfig.credentialResponseEncryptionPolicy) {
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
                    walletEncryptionSupportConfig,
                )?.apply {
                    validate(supportedResponseEncryptionParameters)
                }
            }.getOrNull()

            when (walletEncryptionSupportConfig.credentialResponseEncryptionPolicy) {
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
                walletEncryptionSupportConfig,
            )?.apply {
                validate(supportedResponseEncryptionParameters)
            }
            ensureNotNull(maybeSpec) { IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided() }
        }
    }
}

/**
 * Creates an encryption specification for a credential request based on the supported encryption
 * preferences and configurations provided by the issuer and wallet.
 *
 * This function validates the compatibility of the encryption specification with the
 * supported request encryption parameters from the issuer. It ensures that the necessary
 * encryption keys, methods, and compression algorithms are supported and adhere to the issuer's requirements.
 * If the issuer requires encryption and a valid specification cannot be formulated,
 * an exception is thrown.
 *
 * @param issuerSupportedCredentialRequestEncryption The supported credential request encryption
 * configuration from the issuer indicating whether encryption is supported, required, or not supported.
 * @param walletEncryptionSupportConfig The OpenId4VCI configuration containing encryption-related settings and other configurations
 * for the credential issuance process.
 * @param requestEncryptionSpecFactory A factory function that generates an EncryptionSpec based on
 * the issuer's supported encryption parameters and wallet's encryption configuration.
 * @return A result containing the generated encryption specification (EncryptionSpec) or null if encryption is not supported
 * or required by the issuer.
 */
private fun requestEncryptionSpec(
    issuerSupportedCredentialRequestEncryption: CredentialRequestEncryption,
    walletEncryptionSupportConfig: EncryptionSupportConfig,
    requestEncryptionSpecFactory: RequestEncryptionSpecFactory,
): Result<EncryptionSpec?> = runCatching {
    fun EncryptionSpec.validate(
        issuerSupportedRequestEncryptionParameters: SupportedRequestEncryptionParameters,
    ) {
        ensure(jwk in issuerSupportedRequestEncryptionParameters.encryptionKeys.keys) {
            RequestEncryptionKeyNotAnIssuerKey()
        }
        ensure(encryptionMethod in issuerSupportedRequestEncryptionParameters.encryptionMethods) {
            RequestEncryptionMethodNotSupportedByIssuer()
        }
        compressionAlgorithm?.let {
            ensure(issuerSupportedRequestEncryptionParameters.payloadCompression is PayloadCompression.Supported) {
                IssuerDoesNotSupportEncryptedPayloadCompression()
            }
            ensure(it in issuerSupportedRequestEncryptionParameters.payloadCompression.algorithms) {
                IssuerDoesNotSupportEncryptedPayloadCompressionAlgorithm()
            }
        }
    }

    when (val encryption = issuerSupportedCredentialRequestEncryption) {
        CredentialRequestEncryption.NotSupported -> null

        is CredentialRequestEncryption.SupportedNotRequired -> {
            val issuerSupportedRequestEncryptionParameters = encryption.encryptionParameters
            runCatching {
                requestEncryptionSpecFactory(
                    issuerSupportedRequestEncryptionParameters,
                    walletEncryptionSupportConfig,
                )?.apply {
                    validate(issuerSupportedRequestEncryptionParameters)
                }
            }.getOrNull()
        }

        is CredentialRequestEncryption.Required -> {
            val issuerSupportedRequestEncryptionParameters = encryption.encryptionParameters
            val maybeSpec = requestEncryptionSpecFactory(
                issuerSupportedRequestEncryptionParameters,
                walletEncryptionSupportConfig,
            )?.apply {
                validate(issuerSupportedRequestEncryptionParameters)
            }
            ensureNotNull(maybeSpec) {
                IssuerRequiresEncryptedRequestButEncryptionSpecCannotBeFormulated()
            }
        }
    }
}
