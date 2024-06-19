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

import com.authlete.cose.constants.COSEAlgorithms
import com.authlete.cose.constants.COSEEllipticCurves
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.internal.ClaimSetSerializer
import kotlinx.serialization.Serializable
import java.security.Signature
import java.time.Clock
import java.time.Instant

/**
 * State holding the authorization request as a URL to be passed to front-channel for retrieving an authorization code in an oAuth2
 * authorization code grant type flow.
 * @param authorizationCodeURL the authorization code URL
 * Contains all the parameters
 * @param pkceVerifier the PKCE verifier, which was used
 * for preparing the authorization request
 * @param state the state which was sent with the
 * authorization request
 */
data class AuthorizationRequestPrepared(
    val authorizationCodeURL: HttpsUrl,
    val pkceVerifier: PKCEVerifier,
    val state: String,
) : java.io.Serializable

/**
 * Sealed hierarchy of states describing an authorized issuance request. These states hold an access token issued by the
 * authorization server that protects the credential issuer.
 */
sealed interface AuthorizedRequest : java.io.Serializable {

    /**
     * Access token authorizing the request(s) to issue credential(s)
     */
    val accessToken: AccessToken
    val refreshToken: RefreshToken?
    val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?
    val timestamp: Instant

    fun isAccessTokenExpired(clock: Clock): Boolean = accessToken.isExpired(timestamp, clock.instant())
    fun isRefreshTokenExpired(clock: Clock): Boolean? = refreshToken?.isExpired(timestamp, clock.instant())

    /**
     * Issuer authorized issuance
     *
     * @param accessToken Access token authorizing credential issuance
     * @param refreshToken Refresh token to refresh the access token, if needed
     * @param credentialIdentifiers authorization details, if provided by the token endpoint
     * @param timestamp the point in time of the authorization (when tokens were issued)
     */
    data class NoProofRequired(
        override val accessToken: AccessToken,
        override val refreshToken: RefreshToken?,
        override val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
        override val timestamp: Instant,
    ) : AuthorizedRequest

    /**
     * Issuer authorized issuance and required the provision of proof of holder's binding to be provided
     * along with the request
     *
     * @param accessToken  Access token authorizing certificate issuance
     * @param refreshToken Refresh token to refresh the access token, if needed
     * @param cNonce Nonce value provided by issuer to be included in proof of holder's binding
     * @param credentialIdentifiers authorization details, if provided by the token endpoint
     * @param timestamp the point in time of the authorization (when tokens were issued)
     */
    data class ProofRequired(
        override val accessToken: AccessToken,
        override val refreshToken: RefreshToken?,
        val cNonce: CNonce,
        override val credentialIdentifiers: Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>>?,
        override val timestamp: Instant,
    ) : AuthorizedRequest
}

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
sealed interface SubmittedRequest : java.io.Serializable {

    /**
     * State that denotes the successful submission of an issuance request
     * @param credentials The outcome of the issuance request.
     * If the issuance request was a batch request, it will contain the results of each issuance request.
     * If it was a single issuance request list will contain only one result.
     * @param cNonce Nonce information sent back from the issuance server.
     */
    data class Success(
        val credentials: List<IssuedCredential>,
        val cNonce: CNonce?,
    ) : SubmittedRequest

    /**
     * Sealed hierarchy of erroneous credential issuance request
     */
    sealed interface Errored : SubmittedRequest

    /**
     * State that denotes that the credential issuance request has failed
     *
     * @param error The error that caused the failure of the request
     */
    data class Failed(
        val error: CredentialIssuanceError,
    ) : Errored

    /**
     * State denoting a special case of request failure. Issuer has responded that the proof of possession provided in
     * the request was invalid. Along with the error, issuer responds with a new c_nonce to be used in the request retry.
     *
     * @param cNonce The c_nonce provided from issuer along the error
     * @param errorDescription Description of the error that caused the failure
     */
    data class InvalidProof(
        val cNonce: CNonce,
        val errorDescription: String? = null,
    ) : Errored
}

interface AuthorizeIssuance {

    /**
     * Initial step to authorize an issuance request using Authorized Code Flow.
     * If the specified authorization server supports PAR,
     * then this method executes the first step of PAR by pushing the authorization
     * request to authorization server's 'par endpoint'.
     * If PAR is not supported, then this method prepares the authorization request as a typical authorization code flow authorization
     * request with the request's elements as query parameters.
     * @param walletState an optional parameter that if provided will
     * be included in the authorization request. If it is not provided,
     * a random value will be used
     * @see <a href="https://www.rfc-editor.org/rfc/rfc7636.html">RFC7636</a>
     * @return an HTTPS URL of the authorization request to be placed
     */
    suspend fun prepareAuthorizationRequest(walletState: String? = null): Result<AuthorizationRequestPrepared>

    /**
     * Using the access code retrieved after performing the authorization request prepared from a call to
     * [AuthorizeOfferIssuance.prepareAuthorizationRequest()], it posts a request to authorization server's token endpoint to
     * retrieve an access token. This step transitions state from [AuthorizationRequestPrepared] to an
     * [AuthorizedRequest] state
     *
     * @param authorizationCode The authorization code returned from authorization server via front-channel
     * @param serverState The state returned from authorization server via front-channel
     * @return an issuance request in authorized state
     */
    suspend fun AuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
    ): Result<AuthorizedRequest>

    /**
     * Action to authorize an issuance request using Pre-Authorized Code Flow.
     *
     * @param txCode   Optional parameter in case the credential offer specifies that a user provided pin is required for authorization
     * @return an issuance request in authorized state
     */
    suspend fun authorizeWithPreAuthorizationCode(txCode: String?): Result<AuthorizedRequest>
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
        val claimSet: ClaimSet?,
    ) : IssuanceRequestPayload
}

/**
 * An interface for submitting a credential issuance request. Contains all the operation available to transition an [AuthorizedRequest]
 * to a [SubmittedRequest]
 */
interface RequestIssuance {

    /**
     *  Requests the issuance of a single credential having an [AuthorizedRequest.NoProofRequired] authorization.
     *
     *  @param requestPayload   The payload of the request.
     *  @return The new state of the request or error.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestSingle(
        requestPayload: IssuanceRequestPayload,
    ): Result<SubmittedRequest>

    /**
     *  Requests the issuance of a single credential having an [AuthorizedRequest.ProofRequired] authorization. In this
     *  case caller must provide a binding key that will be used for generating a Proof of Possession that issuer expects.
     *
     *  @param requestPayload   The payload of the request.
     *  @param proofSigner  Signer component of the proof to be sent.
     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestSingle(
        requestPayload: IssuanceRequestPayload,
        proofSigner: PopSigner,
    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.NoProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.

     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.NoProofRequired.requestBatch(
        credentialsMetadata: List<IssuanceRequestPayload>,
    ): Result<SubmittedRequest>

    /**
     *  Batch request for issuing multiple credentials having an [AuthorizedRequest.ProofRequired] authorization.
     *
     *  @param credentialsMetadata   The metadata specifying the credentials that will be requested.
     *  @return The new state of request or error.
     */
    suspend fun AuthorizedRequest.ProofRequired.requestBatch(
        credentialsMetadata: List<Pair<IssuanceRequestPayload, PopSigner>>,
    ): Result<SubmittedRequest>

    /**
     * Special purpose operation to handle the case an 'invalid_proof' error response was received from issuer with
     * fresh c_nonce provided to be used with a request retry.
     *
     * @param cNonce    The c_nonce provided from issuer along the 'invalid_proof' error code.
     * @return The new state of the request.
     */
    suspend fun AuthorizedRequest.NoProofRequired.handleInvalidProof(
        cNonce: CNonce,
    ): AuthorizedRequest.ProofRequired
}

sealed interface DeferredCredentialQueryOutcome {

    data class Issued(val credential: IssuedCredential.Issued) : DeferredCredentialQueryOutcome

    data class IssuancePending(
        val interval: Long? = null,
    ) : DeferredCredentialQueryOutcome

    data class Errored(
        val error: String,
        val errorDescription: String? = null,
    ) : DeferredCredentialQueryOutcome
}

/**
 * An interface for submitting a deferred credential issuance request.
 */
fun interface QueryForDeferredCredential {

    /**
     * Given an authorized request submits a deferred credential request for an identifier of a Deferred Issuance transaction.
     *
     * @param deferredCredential The identifier of a Deferred Issuance transaction.
     * @return The result of the submission.
     */
    suspend fun AuthorizedRequest.queryForDeferredCredential(
        deferredCredential: IssuedCredential.Deferred,
    ): Result<DeferredCredentialQueryOutcome>
}

sealed interface CredentialIssuanceEvent {

    val id: NotificationId
    val description: String?

    data class Accepted(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent

    data class Failed(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent

    data class Deleted(
        override val id: NotificationId,
        override val description: String?,
    ) : CredentialIssuanceEvent
}

fun interface NotifyIssuer {

    suspend fun AuthorizedRequest.notify(
        event: CredentialIssuanceEvent,
    ): Result<Unit>
}

@JvmInline
value class CoseAlgorithm private constructor(val value: Int) {

    fun name(): String =
        checkNotNull(COSEAlgorithms.getNameByValue(value)) { "Cannot find name for COSE algorithm $value" }

    companion object {

        val ES256 = CoseAlgorithm(COSEAlgorithms.ES256)
        val ES384 = CoseAlgorithm(COSEAlgorithms.ES384)
        val ES512 = CoseAlgorithm(COSEAlgorithms.ES512)

        operator fun invoke(value: Int): Result<CoseAlgorithm> = runCatching {
            require(COSEAlgorithms.getNameByValue(value) != null) { "Unsupported COSE algorithm $value" }
            CoseAlgorithm(value)
        }

        operator fun invoke(name: String): Result<CoseAlgorithm> = runCatching {
            val value = COSEAlgorithms.getValueByName(name)
            require(value != 0) { "Unsupported COSE algorithm $name" }
            CoseAlgorithm(value)
        }
    }
}

@JvmInline
value class CoseCurve private constructor(val value: Int) {

    fun name(): String =
        checkNotNull(COSEEllipticCurves.getNameByValue(value)) { "Cannot find name for COSE Curve $value" }

    companion object {

        val P_256 = CoseCurve(COSEEllipticCurves.P_256)
        val P_384 = CoseCurve(COSEEllipticCurves.P_384)
        val P_521 = CoseCurve(COSEEllipticCurves.P_521)

        operator fun invoke(value: Int): Result<CoseCurve> = runCatching {
            require(COSEEllipticCurves.getNameByValue(value) != null) { "Unsupported COSE Curve $value" }
            CoseCurve(value)
        }

        operator fun invoke(name: String): Result<CoseCurve> = runCatching {
            val value = COSEEllipticCurves.getValueByName(name)
            require(value != 0) { "Unsupported COSE Curve $name" }
            CoseCurve(value)
        }
    }
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
 * Interface for implementing the signing process of a proof. It extends [JWSSigner] of nimbus.
 * Implementations should be initialized with the specifics of the proof signing, that is the binding key to be included
 * in the proof and the signing algorithm that will be used for signing.
 */
@Deprecated(
    message = "Deprecated. Will be removed in a future release.",
    replaceWith = ReplaceWith("this.toPopSigner()"),
)
interface ProofSigner : JWSSigner {

    fun getBindingKey(): JwtBindingKey

    fun getAlgorithm(): JWSAlgorithm

    fun toPopSigner(): PopSigner.Jwt = PopSigner.Jwt(getAlgorithm(), getBindingKey(), this)
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
    data object InvalidAuthorizationState : CredentialIssuanceError("InvalidAuthorizationState") {
        private fun readResolve(): Any = InvalidAuthorizationState
    }

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
     * Issuance server does not support notifications
     */
    data object IssuerDoesNotSupportNotifications : CredentialIssuanceError("IssuerDoesNotSupportNotifications") {
        private fun readResolve(): Any = IssuerDoesNotSupportNotifications
    }

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

        /**
         * Proof type signing algorithm provided for specific credential is not supported from issuance server
         */
        data object ProofTypeSigningAlgorithmNotSupported :
            ProofGenerationError("ProofTypeSigningAlgorithmNotSupported") {
            private fun readResolve(): Any = ProofTypeSigningAlgorithmNotSupported
        }

        /**
         * Proof type curve provided for specific credential is not supported from issuance server
         */
        data object ProofTypeSigningCurveNotSupported :
            ProofGenerationError("ProofTypeSigningCurveNotSupported") {
            private fun readResolve(): Any = ProofTypeSigningCurveNotSupported
        }
    }

    /**
     * Sealed hierarchy of errors related to validation of encryption parameters passed along with the issuance request.
     */
    sealed class ResponseEncryptionError(message: String) : CredentialIssuanceError(message) {

        /**
         * Wallet requires Credential Response encryption, but it is not supported by the issuance server.
         */
        data object ResponseEncryptionRequiredByWalletButNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionRequiredByWalletButNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionRequiredByWalletButNotSupportedByIssuer
        }

        /**
         * Response encryption algorithm specified in request is not supported from issuance server
         */
        data object ResponseEncryptionAlgorithmNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionAlgorithmNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionAlgorithmNotSupportedByIssuer
        }

        /**
         * Response encryption method specified in request is not supported from issuance server
         */
        data object ResponseEncryptionMethodNotSupportedByIssuer :
            ResponseEncryptionError("ResponseEncryptionMethodNotSupportedByIssuer") {
            private fun readResolve(): Any = ResponseEncryptionMethodNotSupportedByIssuer
        }

        /**
         * Issuer enforces encrypted responses but encryption parameters not provided in request
         */
        data object IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided :
            ResponseEncryptionError("IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided") {
            private fun readResolve(): Any = IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided
        }

        /**
         * Wallet requires Credential Response encryption, but no crypto material can be generated for the issuance server.
         */
        data object WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated :
            ResponseEncryptionError("WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated") {
            private fun readResolve(): Any = WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated
        }
    }

    /**
     * Batch credential request syntax is incorrect. Encryption information included in individual requests while shouldn't
     */
    data object BatchRequestHasEncryptionSpecInIndividualRequests : CredentialIssuanceError(
        "BatchRequestContainsEncryptionOnIndividualRequest",
    ) {
        private fun readResolve(): Any = BatchRequestHasEncryptionSpecInIndividualRequests
    }

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
