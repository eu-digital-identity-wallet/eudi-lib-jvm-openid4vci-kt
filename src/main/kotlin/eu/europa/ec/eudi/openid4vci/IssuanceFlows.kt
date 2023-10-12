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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWT
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultAuthorizationCodeFlowIssuer
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultPreAuthorizedCodeFlowIssuer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant

/**
 * Sealed interface that defines the states of a credential issuance that follows the Authorization Code Flow
 * of OpenId4VCI specification.
 */
sealed interface AuthCodeFlowIssuance {

    /**
     * State denoting that the pushed authorization request has been placed successfully and response processed
     */
    data class ParRequested(
        val credentials: List<OfferedCredential>,
        val getAuthorizationCodeURL: GetAuthorizationCodeURL,
        val pkceVerifier: PKCEVerifier,
        val state: String,
    ) : AuthCodeFlowIssuance

    /**
     * State denoting that caller has followed the [ParRequested.getAuthorizationCodeURL] URL and response received
     * from authorization server and processed successfully.
     */
    data class AuthorizationCodeRetrieved(
        val credentials: List<OfferedCredential>,
        val authorizationCode: IssuanceAuthorization.AuthorizationCode,
        val pkceVerifier: PKCEVerifier,
    ) : AuthCodeFlowIssuance

    /**
     * State denoting that the access token was requested from authorization server and response received and processed successfully
     */
    sealed interface Authorized : AuthCodeFlowIssuance {

        val credentials: List<OfferedCredential>
        val token: IssuanceAccessToken

        /**
         * Issuer authorized issuance
         *
         * @param token Access token authorizing certificate issuance
         */
        data class NoProofRequired(
            override val credentials: List<OfferedCredential>,
            override val token: IssuanceAccessToken,
        ) : Authorized

        /**
         * Issuer authorized issuance and requires the provision of proof of holder's binding to be provided
         * along with the request
         *
         * @param token  Access token authorizing certificate issuance
         * @param cNonce Nonce value provided by issuer to be included in proof of holder's binding
         */
        data class ProofRequired(
            override val credentials: List<OfferedCredential>,
            override val token: IssuanceAccessToken,
            val cNonce: CNonce,
        ) : Authorized
    }

    sealed interface Requested {

        data class Success(
            val response: IssuanceResponse,
        ) : Requested

        sealed interface Failure : Requested {
            val error: CredentialIssuanceError
        }

        data class GenericFailure(
            override val error: CredentialIssuanceError,
        ) : Failure

        class NonceMissing private constructor(
            override val error: CredentialIssuanceError.InvalidProof,
            val credentials: List<OfferedCredential>,
            val token: IssuanceAccessToken,
            val cNonce: CNonce,
        ) : Failure {

            companion object {
                operator fun invoke(
                    error: CredentialIssuanceError.InvalidProof,
                    credentials: List<OfferedCredential>,
                    token: IssuanceAccessToken,
                ): NonceMissing {
                    require(credentials.isNotEmpty()) { "Property credentials cannot be empty" }

                    return NonceMissing(
                        error = error,
                        credentials = credentials,
                        token = token,
                        cNonce = CNonce(
                            error.cNonce,
                            error.cNonceExpiresIn,
                        ),
                    )
                }
            }
        }
    }
}

/**
 * Sealed interface that defines the states of a credential's issuance that follows the Pre-Authorization Code Flow of OpenId4VCI specification.
 */
sealed interface PreAuthCodeFlowIssuance {

    /**
     * State denoting that caller has been already authorized against the credential issuer and a pre-authorized code was offered.
     */
    data class Authorized(
        val authorizationCode: IssuanceAuthorization.PreAuthorizationCode,
    ) : PreAuthCodeFlowIssuance

    /**
     * State denoting that the access token was requested from authorization server and response received and processed successfully
     */
    data class AccessTokenRetrieved(
        val token: IssuanceAccessToken,
    ) : PreAuthCodeFlowIssuance

    /**
     * State denoting that the certificate issuance was requested and certificate issued and received successfully
     */
    data class Issued(
        val issuedAt: Instant,
        val certificate: IssuedCertificate,
    ) : PreAuthCodeFlowIssuance
}

/**
 * Errors that can happen in the process of issuance process
 */
sealed interface CredentialIssuanceError {

    /**
     * Failure when placing Pushed Authorization Request to Authorization Server
     */
    data class PushedAuthorizationRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError

    /**
     * Failure when requesting access token from Authorization Server
     */
    data class AccessTokenRequestFailed(
        val error: String,
        val errorDescription: String?,
    ) : CredentialIssuanceError

    /**
     * Failure when creating an issuance request
     */
    data class InvalidIssuanceRequest(
        val message: String,
    ) : CredentialIssuanceError

    /**
     * Issuer rejected issuance request because no c_nonce was provided along with the proof. A fresh c_nonce is provided by issuer.
     */
    data class InvalidProof(
        val cNonce: String,
        val cNonceExpiresIn: Long,
    ) : CredentialIssuanceError

    /**
     * Issuer has not issued yet deferred credential. Retry interval (in seconds) is provided to caller
     */
    data class DeferredCredentialIssuancePending(
        val retryInterval: Long = 5,
    ) : CredentialIssuanceError

    /**
     * Invalid access token passed to issuance server
     */
    object InvalidToken : CredentialIssuanceError
    object InvalidTransactionId : CredentialIssuanceError
    object UnsupportedCredentialType : CredentialIssuanceError
    object UnsupportedCredentialFormat : CredentialIssuanceError
    object InvalidEncryptionParameters : CredentialIssuanceError

    data class IssuanceRequestFailed(
        val error: String,
        val errorDescription: String? = null,
    ) : CredentialIssuanceError

    data class ResponseUnparsable(val error: String) : CredentialIssuanceError
}

/**
 * Convert Error to throwable
 */
fun CredentialIssuanceError.asException() = CredentialIssuanceException(this)

/**
 * Exception denoting that a [CredentialIssuanceError] error happened in the process of a certificate issuance
 */
data class CredentialIssuanceException(val error: CredentialIssuanceError) : RuntimeException()

/**
 * Holds a https [java.net.URL] to be used at the second step of PAR flow for retrieving the authorization code.
 * Contains the 'request_uri' retrieved from the post to PAR endpoint of authorization server and the client_id.
 */
class GetAuthorizationCodeURL private constructor(
    val url: HttpsUrl,
) {
    override fun toString(): String {
        return url.toString()
    }

    companion object {
        val PARAM_CLIENT_ID = "client_id"
        val PARAM_REQUEST_URI = "request_uri"
        val PARAM_STATE = "state"
        operator fun invoke(url: String): GetAuthorizationCodeURL {
            val httpsUrl = HttpsUrl(url).getOrThrow()
            require(
                httpsUrl.value.query != null && httpsUrl.value.query.contains("$PARAM_CLIENT_ID="),
            ) { "URL must contain client_id query parameter" }
            require(
                httpsUrl.value.query != null && httpsUrl.value.query.contains("$PARAM_REQUEST_URI="),
            ) { "URL must contain request_uri query parameter" }

            return GetAuthorizationCodeURL(httpsUrl)
        }
    }
}

/**
 * Credential(s) issuance request
 */
sealed interface CredentialIssuanceRequest {

    /**
     * Models an issuance request for a batch of credentials
     */
    data class BatchCredentials(
        val credentialRequests: List<SingleCredential>,
    ) : CredentialIssuanceRequest

    /**
     * Models an issuance request for a single credential
     */
    sealed interface SingleCredential : CredentialIssuanceRequest {

        val format: String
        val proof: Proof?
        val credentialEncryptionJwk: JWK?
        val credentialResponseEncryptionAlg: JWEAlgorithm?
        val credentialResponseEncryptionMethod: EncryptionMethod?

        fun requiresEncryptedResponse(): Boolean =
            credentialResponseEncryptionAlg != null && credentialEncryptionJwk != null && credentialResponseEncryptionMethod != null

        /**
         * Issuance request for a credential of mso_mdoc format
         */
        class MsoMdocIssuanceRequest private constructor(
            val doctype: String,
            override val proof: Proof? = null,
            override val credentialEncryptionJwk: JWK? = null,
            override val credentialResponseEncryptionAlg: JWEAlgorithm? = null,
            override val credentialResponseEncryptionMethod: EncryptionMethod? = null,
            val claims:
                Map<Namespace, Map<ClaimName, CredentialSupportedObject.MsoMdocCredentialCredentialSupportedObject.ClaimObject>>? = null,
        ) : SingleCredential {

            override val format: String = "mso_mdoc"

            companion object {
                operator fun invoke(
                    proof: Proof? = null,
                    credentialEncryptionJwk: JWK? = null,
                    credentialResponseEncryptionAlg: JWEAlgorithm? = null,
                    credentialResponseEncryptionMethod: EncryptionMethod? = null,
                    doctype: String,
                    claims: Map<
                        Namespace,
                        Map<ClaimName, CredentialSupportedObject.MsoMdocCredentialCredentialSupportedObject.ClaimObject>,
                        >? = null,
                ): Result<MsoMdocIssuanceRequest> = runCatching {
                    var encryptionMethod = credentialResponseEncryptionMethod
                    if (credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null) {
                        encryptionMethod = EncryptionMethod.A256GCM
                    } else if (credentialResponseEncryptionAlg != null && credentialEncryptionJwk == null) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest("Encryption algorithm was provided but no encryption key")
                            .asException()
                    } else if (credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest(
                            "Credential response encryption algorithm must be specified if Credential " +
                                "response encryption method is provided",
                        ).asException()
                    }

                    MsoMdocIssuanceRequest(
                        proof = proof,
                        credentialEncryptionJwk = credentialEncryptionJwk,
                        credentialResponseEncryptionAlg = credentialResponseEncryptionAlg,
                        credentialResponseEncryptionMethod = encryptionMethod,
                        doctype = doctype,
                        claims = claims,
                    )
                }
            }
        }
    }
}

data class DeferredCredentialRequest(
    val transactionId: String,
    val token: IssuanceAccessToken,
)

sealed interface IssuanceResponse {

    data class Batch(
        val credentialResponses: List<Result>,
        val cNonce: String? = null,
        val cNonceExpiresIn: Long? = null,
    ) : IssuanceResponse

    data class Single(
        val format: String,
        val result: Result,
        val cNonce: String? = null,
        val cNonceExpiresInSeconds: Long? = null,
    ) : IssuanceResponse

    sealed interface Result {
        data class Complete(
            val credential: String,
        ) : Result

        data class Deferred(
            val transactionId: String,
        ) : Result
    }
}

sealed interface Proof {
    fun toJsonObject(): JsonObject

    data class Jwt(
        val jwt: JWT,
    ) : Proof {
        override fun toJsonObject(): JsonObject =
            JsonObject(
                mapOf(
                    "proof_type" to JsonPrimitive("jwt"),
                    "jwt" to JsonPrimitive(jwt.serialize()),
                ),
            )
    }

    data class Cwt(
        val cwt: String,
    ) : Proof {
        override fun toJsonObject(): JsonObject =
            JsonObject(
                mapOf(
                    "proof_type" to JsonPrimitive("cwt"),
                    "jwt" to JsonPrimitive(cwt),
                ),
            )
    }
}

/**
 * Interface that defines the state transitions that are happening in a credential issuance process that follows
 * the Authorization Code Flow of OpenId4VCI specification.
 */
interface AuthorizationCodeFlowIssuer {
    suspend fun placePushedAuthorizationRequest(
        credentials: List<OfferedCredential>,
        issuerState: String?,
    ): Result<AuthCodeFlowIssuance.ParRequested>

    suspend fun AuthCodeFlowIssuance.ParRequested.completePar(
        authorizationCode: String,
    ): Result<AuthCodeFlowIssuance.AuthorizationCodeRetrieved>

    suspend fun AuthCodeFlowIssuance.AuthorizationCodeRetrieved.placeAccessTokenRequest(): Result<AuthCodeFlowIssuance.Authorized>

    suspend fun AuthCodeFlowIssuance.Authorized.NoProofRequired.requestIssuance(
        claims: ClaimSet,
    ): Result<AuthCodeFlowIssuance.Requested>

    suspend fun AuthCodeFlowIssuance.Authorized.ProofRequired.requestIssuance(
        proof: Proof,
        claims: ClaimSet,
    ): Result<AuthCodeFlowIssuance.Requested>

    suspend fun AuthCodeFlowIssuance.Requested.NonceMissing.reProcess(): AuthCodeFlowIssuance.Authorized.ProofRequired

    companion object {
        fun make(
            authorizer: IssuanceAuthorizer,
            requester: IssuanceRequester,
        ) = DefaultAuthorizationCodeFlowIssuer(authorizer, requester)

        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            issuerMetadata: CredentialIssuerMetadata,
            config: WalletOpenId4VCIConfig,
        ) = DefaultAuthorizationCodeFlowIssuer(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
            ),
            IssuanceRequester.ktor(
                issuerMetadata = issuerMetadata,
            ),
        )
    }
}

interface PreAuthorizationCodeFlowIssuer {

    suspend fun authorize(preAuthorizedCode: String, pin: String): Result<PreAuthCodeFlowIssuance.Authorized>

    suspend fun PreAuthCodeFlowIssuance.Authorized.placeAccessTokenRequest(): Result<PreAuthCodeFlowIssuance.AccessTokenRetrieved>

    suspend fun PreAuthCodeFlowIssuance.AccessTokenRetrieved.issueCredential(): Result<PreAuthCodeFlowIssuance.Issued>

    companion object {
        fun make(authorizer: IssuanceAuthorizer) = DefaultPreAuthorizedCodeFlowIssuer(authorizer)

        fun ktor(
            authorizationServerMetadata: CIAuthorizationServerMetadata,
            config: WalletOpenId4VCIConfig,
        ) = DefaultPreAuthorizedCodeFlowIssuer(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
            ),
        )
    }
}
