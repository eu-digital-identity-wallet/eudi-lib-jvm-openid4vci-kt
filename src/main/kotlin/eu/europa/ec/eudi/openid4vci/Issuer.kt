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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuer
import eu.europa.ec.eudi.openid4vci.internal.issuance.IssuanceAuthorizer
import eu.europa.ec.eudi.openid4vci.internal.issuance.IssuanceRequester
import eu.europa.ec.eudi.openid4vci.internal.issuance.KeyGenerator
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Aggregation interface providing all functionality required for performing a credential issuance request (batch or single)
 * Provides factory methods for creating implementations of this interface.
 */
interface Issuer : AuthorizeIssuance, RequestIssuance, QueryForDeferredCredential {

    companion object {

        /**
         * Factory method to create an [Issuer] using the passed http client factory
         *
         * @param authorizationServerMetadata   The authorization server metadata required from the underlying [IssuanceAuthorizer] component.
         * @param issuerMetadata    The credential issuer metadata required from the underlying [IssuanceRequester] component.
         * @param config    Configuration object
         * @return An instance of Issuer based on ktor
         */
        fun make(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            issuerMetadata: CredentialIssuerMetadata,
            config: OpenId4VCIConfig,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ): Issuer = DefaultIssuer(
            authorizationServerMetadata,
            issuerMetadata,
            config,
            ktorHttpClientFactory,
            coroutineDispatcher,
            responseEncryptionSpecFactory,
        )

        val DefaultResponseEncryptionSpecFactory: ResponseEncryptionSpecFactory = { requiredEncryption ->
            requiredEncryption.algorithmsSupported.mapNotNull { alg ->
                val encryptionKey = when {
                    JWEAlgorithm.Family.ECDH_ES.contains(alg) ->
                        KeyGenerator.randomECEncryptionKey(Curve.P_256)

                    JWEAlgorithm.Family.RSA.contains(alg) ->
                        KeyGenerator.randomRSAEncryptionKey(2048)

                    else -> null
                }

                encryptionKey?.let {
                    IssuanceResponseEncryptionSpec(
                        jwk = it,
                        algorithm = alg,
                        encryptionMethod = requiredEncryption.encryptionMethodsSupported[0],
                    )
                }
            }.firstOrNull() ?: error("Could not create encryption spec")
        }
    }
}

/**
 * Errors that can happen in the process of issuance process
 */
sealed class CredentialIssuanceError(message: String) : Throwable(message) {

    /**
     * Failure when placing Pushed Authorization Request to Authorization Server
     */
    data class PushedAuthorizationRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when requesting access token from Authorization Server
     */
    data class AccessTokenRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Failure when creating an issuance request
     */
    class InvalidIssuanceRequest(
        message: String,
    ) : CredentialIssuanceError(message)

    /**
     * Issuer rejected the issuance request because no c_nonce was provided along with the proof.
     * A fresh c_nonce is provided by the issuer.
     */
    data class InvalidProof(
        val cNonce: String,
        val cNonceExpiresIn: Long? = 5,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("Invalid Proof")

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError("DeferredCredentialIssuancePending")

    /**
     * Invalid access token passed to issuance server
     */
    data object InvalidToken : CredentialIssuanceError("InvalidToken") {
        private fun readResolve(): Any = InvalidToken
    }

    /**
     * Invalid transaction id passed to issuance server in the context of deferred credential requests
     */
    data object InvalidTransactionId : CredentialIssuanceError("InvalidTransactionId") {
        private fun readResolve(): Any = InvalidTransactionId
    }

    /**
     * Invalid credential type requested to issuance server
     */
    data object UnsupportedCredentialType : CredentialIssuanceError("UnsupportedCredentialType") {
        private fun readResolve(): Any = UnsupportedCredentialType
    }

    /**
     * Un-supported credential type requested to issuance server
     */
    data object UnsupportedCredentialFormat : CredentialIssuanceError("UnsupportedCredentialFormat") {
        private fun readResolve(): Any = UnsupportedCredentialFormat
    }

    /**
     * Invalid encryption parameters passed to issuance server
     */
    data object InvalidEncryptionParameters : CredentialIssuanceError("InvalidEncryptionParameters") {
        private fun readResolve(): Any = InvalidEncryptionParameters
    }

    /**
     * Issuance server does not support batch credential requests
     */
    data object IssuerDoesNotSupportBatchIssuance : CredentialIssuanceError("IssuerDoesNotSupportBatchIssuance") {
        private fun readResolve(): Any = IssuerDoesNotSupportBatchIssuance
    }

    /**
     * Issuance server does not support deferred credential issuance
     */
    data object IssuerDoesNotSupportDeferredIssuance : CredentialIssuanceError("IssuerDoesNotSupportDeferredIssuance") {
        private fun readResolve(): Any = IssuerDoesNotSupportDeferredIssuance
    }

    /**
     * Generic failure during issuance request
     */
    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Issuance server response is un-parsable
     */
    data class ResponseUnparsable(val error: String) : CredentialIssuanceError("ResponseUnparsable")

    /**
     * Sealed hierarchy of errors related to proof generation
     */
    sealed class ProofGenerationError(message: String) : CredentialIssuanceError(message) {

        /**
         * Binding method specified is not supported from issuer server
         */
        data object CryptographicSuiteNotSupported : ProofGenerationError("BindingMethodNotSupported") {
            private fun readResolve(): Any = CryptographicSuiteNotSupported
        }

        /**
         * Cryptographic binding method is not supported from the issuance server for a specific credential
         */
        data object CryptographicBindingMethodNotSupported :
            ProofGenerationError("CryptographicBindingMethodNotSupported") {
            private fun readResolve(): Any = CryptographicBindingMethodNotSupported
        }

        /**
         * Proof type provided for specific credential is not supported from issuance server
         */
        data object ProofTypeNotSupported : ProofGenerationError("ProofTypeNotSupported") {
            private fun readResolve(): Any = ProofTypeNotSupported
        }
    }

    /**
     * Sealed hierarchy of errors related to validation of encryption parameters passed along with the issuance request.
     */
    sealed class ResponseEncryptionError(message: String) : CredentialIssuanceError(message) {

        /**
         * Response encryption algorithm specified in request is not supported from issuance server
         */
        data object ResponseEncryptionAlgorithmNotSupportedByIssuer :
            ProofGenerationError("ResponseEncryptionAlgorithmNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionAlgorithmNotSupportedByIssuer
        }

        /**
         * Response encryption method specified in request is not supported from issuance server
         */
        data object ResponseEncryptionMethodNotSupportedByIssuer :
            ProofGenerationError("ResponseEncryptionMethodNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionMethodNotSupportedByIssuer
        }

        /**
         * Issuer enforces encrypted responses but encryption parameters not provided in request
         */
        data object IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided :
            ProofGenerationError("IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided") {
            private fun readResolve(): Any = IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
        }
    }
}
