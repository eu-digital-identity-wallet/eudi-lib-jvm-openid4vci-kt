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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.internal.ClaimSetSerializer
import kotlinx.serialization.Serializable
import java.security.Signature

/**
 * The result of a request for issuance
 */
sealed interface IssuedCredential : java.io.Serializable {

    /**
     * Credential was issued from server and the result is returned inline.
     *
     * @param credential The issued credential.
     * @param notificationId The identifier to be used in issuer's notification endpoint.
     */
    data class Issued(
        val credential: String,
        val notificationId: NotificationId? = null,
    ) : IssuedCredential

    /**
     * Credential could not be issued immediately. An identifier is returned from server to be used later on
     * to request the credential from issuer's Deferred Credential Endpoint.
     *
     * @param transactionId  A string identifying a Deferred Issuance transaction.
     */
    data class Deferred(
        val transactionId: TransactionId,
    ) : IssuedCredential
}

/**
 * Sealed hierarchy of states describing the state of an issuance request submitted to a credential issuer.
 */
sealed interface SubmissionOutcome : java.io.Serializable {

    /**
     * State that denotes the successful submission of an issuance request
     * @param credentials The outcome of the issuance request.
     * If the issuance request was a batch request, it will contain the results of each issuance request.
     * If it was a single issuance request list will contain only one result.
     */
    data class Success(val credentials: List<IssuedCredential>) : SubmissionOutcome

    /**
     * State that denotes that the credential issuance request has failed
     *
     * @param error The error that caused the failure of the request
     */
    data class Failed(val error: CredentialIssuanceError) : SubmissionOutcome
}

/**
 * Interface to model the set of specific claims that need to be included in the issued credential.
 * This set of claims is modeled differently depending on the credential format.
 */
sealed interface ClaimSet

@Serializable(with = ClaimSetSerializer::class)
class MsoMdocClaimSet(claims: List<Pair<Namespace, ClaimName>>) :
    ClaimSet,
    List<Pair<Namespace, ClaimName>> by claims

@Serializable
data class GenericClaimSet(val claims: List<ClaimName>) : ClaimSet

/**
 * Sealed interface to model the payload of an issuance request. Issuance can be requested by providing the credential configuration
 * identifier and a claim set ot by providing a credential identifier retrieved from token endpoint while authorizing an issuance request.
 */
sealed interface IssuanceRequestPayload {

    /**
     * Credential identifier based request payload.
     *
     * @param credentialConfigurationIdentifier The credential configuration identifier
     * @param credentialIdentifier  The credential identifier
     */
    data class IdentifierBased(
        val credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
        val credentialIdentifier: CredentialIdentifier,
    ) : IssuanceRequestPayload

    /**
     * Credential configuration based request payload.
     *
     * @param credentialConfigurationIdentifier The credential configuration identifier
     * @param claimSet  Optional parameter to specify the specific set of claims that are requested to be included in the
     *          credential to be issued.
     */
    data class ConfigurationBased(
        val credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
        val claimSet: ClaimSet? = null,
    ) : IssuanceRequestPayload
}

typealias AuthorizedRequestAnd<T> = Pair<AuthorizedRequest, T>

/**
 * An interface for submitting a credential issuance request.
 */
interface RequestIssuance {

    @Deprecated(
        message = "Deprecated and will be removed",
        replaceWith = ReplaceWith("requestSingle(requestPayload, popSigner)"),
    )
    suspend fun AuthorizedRequest.requestSingleAndUpdateState(
        requestPayload: IssuanceRequestPayload,
        popSigner: PopSigner?,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = requestSingle(requestPayload, popSigner)

    /**
     * Places a request to the credential issuance endpoint.
     * Method will attempt to automatically retry submission in case
     * - Initial authorization state is [AuthorizedRequest.NoProofRequired] and
     * - a [popSigner] has been provided
     *
     * @receiver the current authorization state
     * @param requestPayload the payload of the request
     * @param popSigner Signer component of the proof to be sent. Although this is an optional
     * parameter, only required in case the present authorization state is [AuthorizedRequest.ProofRequired],
     * caller is advised to provide it, in order to allow the method to automatically retry
     * in case of [CredentialIssuanceError.InvalidProof]
     *
     * @return the possibly updated [AuthorizedRequest] (if updated it will contain a fresh c_nonce) and
     * the [SubmissionOutcome]
     */
    suspend fun AuthorizedRequest.requestSingle(
        requestPayload: IssuanceRequestPayload,
        popSigner: PopSigner?,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>>
}

@Deprecated(
    message = "Batch endpoint has been removed from OpenId4VCI",
)
interface RequestBatchIssuance {

    @Deprecated(
        message = "Deprecated and will be removed",
        replaceWith = ReplaceWith("requestBatch(credentialsMetadata)"),
    )
    suspend fun AuthorizedRequest.requestBatchAndUpdateState(
        credentialsMetadata: List<Pair<IssuanceRequestPayload, PopSigner?>>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>> = requestBatch(credentialsMetadata)

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.ProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.
     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.requestBatch(
        credentialsMetadata: List<Pair<IssuanceRequestPayload, PopSigner?>>,
    ): Result<AuthorizedRequestAnd<SubmissionOutcome>>
}

sealed interface PopSigner {
    /**
     * A signer for proof of possession JWTs
     * @param algorithm The algorithm used by the singing key
     * @param bindingKey The public key to be included to the proof. It should correspond to the key
     * used to sign the proof.
     * @param jwsSigner A function to sign the JWT
     */
    data class Jwt(
        val algorithm: JWSAlgorithm,
        val bindingKey: JwtBindingKey,
        val jwsSigner: JWSSigner,
    ) : PopSigner

    /**
     * A signer for proof of possession of type CWT
     * @param algorithm The algorithm used by the singing key
     * @param curve the curve used by the singing key
     * @param bindingKey the public key to be included to the proof. It should correspond to the key
     * used to sign the proof. If an instance of [CwtBindingKey.CoseKey] is provided key will be embedded
     * to the protected header under the label "COSE_key". If an instance [CwtBindingKey.X509] the chain
     * will be included in the protected header, as such.
     * @param sign A suspended function to actually sign the data. It is required that implementer, uses
     * the P1363 format
     */
    @Deprecated(
        message = "CWT proofs have been removed from OpenId4VCI",
    )
    data class Cwt(
        val algorithm: CoseAlgorithm,
        val curve: CoseCurve,
        val bindingKey: CwtBindingKey,
        val sign: suspend (ByteArray) -> ByteArray,
    ) : PopSigner

    companion object {

        /**
         * Factory method for creating a [PopSigner.Jwt]
         *
         * Comes handy when caller has access to [privateKey]
         *
         * @param privateKey the key that will be used to sign the JWT
         * @param publicKey the pub key to be included in the JWT. It should form a pair with [privateKey].
         * In case of [JwtBindingKey.Did] this condition is not being checked.
         * @param algorithm The algorithm for signing the JWT
         *
         * @return the JWT signer
         */
        fun jwtPopSigner(
            privateKey: JWK,
            algorithm: JWSAlgorithm,
            publicKey: JwtBindingKey,
        ): Jwt {
            require(privateKey.isPrivate) { "A private key is required" }
            require(
                when (publicKey) {
                    is JwtBindingKey.Did -> true // Would require DID resolution which is out of scope
                    is JwtBindingKey.Jwk -> privateKey.toPublicJWK() == publicKey.jwk
                    is JwtBindingKey.X509 -> privateKey.toPublicJWK() == JWK.parse(publicKey.chain.first())
                },
            ) { "Public/private key don't match" }

            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, algorithm)
            return Jwt(algorithm, publicKey, signer)
        }

        /**
         * Factory method for creating a [PopSigner.Cwt]
         *
         * Comes handy when caller has access to [privateKey]
         *
         * @param privateKey the key that will be used to sign the CWT
         * In case of [JwtBindingKey.Did] this condition is not being checked.
         * @return the CWT signer
         */
        @Deprecated(
            message = "CWT proofs have been removed from OpenId4VCI",
        )
        fun cwtPopSigner(
            privateKey: ECKey,
        ): Cwt {
            fun CoseAlgorithm.signature(): Signature =
                when (this) {
                    CoseAlgorithm.ES256 -> "SHA256withECDSAinP1363Format"
                    CoseAlgorithm.ES384 -> "SHA384withECDSAinP1363Format"
                    CoseAlgorithm.ES512 -> "SHA512withECDSAinP1363Format"
                    else -> error("Unsupported $this")
                }.let { Signature.getInstance(it) }

            val algorithm = CoseAlgorithm(privateKey.algorithm.name).getOrThrow()
            val curve = CoseCurve(privateKey.curve.name).getOrThrow()

            return Cwt(algorithm, curve, CwtBindingKey.CoseKey(privateKey.toPublicJWK())) { data ->
                with(algorithm.signature()) {
                    initSign(privateKey.toECPrivateKey())
                    update(data)
                    sign()
                }
            }
        }
    }
}

/**
 * A factory method that based on the issuer's supported encryption and the wallet's configuration creates the encryption specification
 * that the wallet expects in the response of its issuance request.
 */
typealias ResponseEncryptionSpecFactory =
    (SupportedEncryptionAlgorithmsAndMethods, KeyGenerationConfig) -> IssuanceResponseEncryptionSpec?

/**
 * Errors that can happen in the process of issuance process
 */
sealed class CredentialIssuanceError(message: String) : Throwable(message) {

    /**
     * Indicates that the state returned by the authorization server doesn't match the state
     * included which was included in the authorization request, during authorization code flow
     */
    class InvalidAuthorizationState : CredentialIssuanceError("InvalidAuthorizationState")

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
     * Issuer rejected the issuance request because considered the proof erroneous.
     * It is marked as irrecoverable because it is raised only after the library
     * has automatically retried to recover from an [InvalidProof] error and failed
     */
    data class IrrecoverableInvalidProof(val errorDescription: String? = null) : CredentialIssuanceError("Irrecoverable invalid proof ")

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError("DeferredCredentialIssuancePending")

    /**
     * Invalid access token passed to issuance server
     */
    class InvalidToken : CredentialIssuanceError("InvalidToken")

    /**
     * Invalid transaction id passed to issuance server in the context of deferred credential requests
     */
    class InvalidTransactionId : CredentialIssuanceError("InvalidTransactionId")

    /**
     * Invalid credential type requested to issuance server
     */
    class UnsupportedCredentialType : CredentialIssuanceError("UnsupportedCredentialType")

    /**
     * Un-supported credential type requested to issuance server
     */
    class UnsupportedCredentialFormat : CredentialIssuanceError("UnsupportedCredentialFormat")

    /**
     * Invalid encryption parameters passed to issuance server
     */
    class InvalidEncryptionParameters : CredentialIssuanceError("InvalidEncryptionParameters")

    /**
     * Issuance server does not support batch credential requests
     */
    class IssuerDoesNotSupportBatchIssuance : CredentialIssuanceError("IssuerDoesNotSupportBatchIssuance")

    /**
     * Issuance server does not support deferred credential issuance
     */
    class IssuerDoesNotSupportDeferredIssuance : CredentialIssuanceError("IssuerDoesNotSupportDeferredIssuance")

    /**
     * Generic failure during issuance request
     */
    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError("$error+${errorDescription?.let { " description=$it" }}")

    /**
     * Generic failure during notification
     */
    data class NotificationFailed(
        val error: String,
    ) : CredentialIssuanceError(error)

    /**
     * Issuance server response is un-parsable
     */
    data class ResponseUnparsable(val error: String) : CredentialIssuanceError("ResponseUnparsable")

    /**
     * Sealed hierarchy of errors related to proof generation
     */
    sealed class ProofGenerationError(message: String) : CredentialIssuanceError(message) {

        /**
         * Proof type provided for specific credential is not supported from issuance server
         */
        class ProofTypeNotSupported : ProofGenerationError("ProofTypeNotSupported")

        /**
         * Proof type signing algorithm provided for specific credential is not supported from issuance server
         */
        class ProofTypeSigningAlgorithmNotSupported :
            ProofGenerationError("ProofTypeSigningAlgorithmNotSupported")
    }

    /**
     * Sealed hierarchy of errors related to validation of encryption parameters passed along with the issuance request.
     */
    sealed class ResponseEncryptionError(message: String) : CredentialIssuanceError(message) {

        /**
         * Wallet requires Credential Response encryption, but it is not supported by the issuance server.
         */
        class ResponseEncryptionRequiredByWalletButNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionRequiredByWalletButNotSupportedByIssuer")

        /**
         * Response encryption algorithm specified in request is not supported from issuance server
         */
        class ResponseEncryptionAlgorithmNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionAlgorithmNotSupportedByIssuer")

        /**
         * Response encryption method specified in request is not supported from issuance server
         */
        class ResponseEncryptionMethodNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionMethodNotSupportedByIssuer")

        /**
         * Issuer enforces encrypted responses but encryption parameters not provided in request
         */
        class IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided :
            ResponseEncryptionError("IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided")

        /**
         * Wallet requires Credential Response encryption, but no crypto material can be generated for the issuance server.
         */
        class WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated :
            ResponseEncryptionError("WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated")
    }

    /**
     * Batch credential request syntax is incorrect. Encryption information included in individual requests while shouldn't
     */
    class BatchRequestHasEncryptionSpecInIndividualRequests : CredentialIssuanceError(
        "BatchRequestContainsEncryptionOnIndividualRequest",
    )

    /**
     * Wrong content-type of encrypted response. Content-type of encrypted responses must be application/jwt
     */
    data class InvalidResponseContentType(
        val expectedContentType: String,
        val invalidContentType: String,
    ) : CredentialIssuanceError(
        "Encrypted response content-type expected to be $expectedContentType but instead was $invalidContentType",
    )

    /**
     * Batch response is not syntactical as expected.
     */
    data class InvalidBatchIssuanceResponse(
        val error: String,
    ) : CredentialIssuanceError("Invalid batch issuance response: $error")
}
