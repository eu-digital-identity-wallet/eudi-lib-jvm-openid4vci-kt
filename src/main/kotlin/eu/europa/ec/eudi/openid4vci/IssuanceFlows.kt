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
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultAuthorizationCodeFlowIssuer
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultPreAuthorizedCodeFlowIssuer
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
        val getAuthorizationCodeURL: GetAuthorizationCodeURL,
        val pkceVerifier: PKCEVerifier,
        val state: String,
    ) : AuthCodeFlowIssuance

    /**
     * State denoting that caller has followed the [ParRequested.getAuthorizationCodeURL] URL and response received
     * from authorization server and processed successfully.
     */
    data class Authorized(
        val authorizationCode: IssuanceAuthorization.AuthorizationCode,
        val pkceVerifier: PKCEVerifier,
    ) : AuthCodeFlowIssuance

    /**
     * State denoting that the access token was requested from authorization server and response received and processed successfully
     */
    data class AccessTokenRetrieved(
        val token: IssuanceAccessToken,
    ) : AuthCodeFlowIssuance

    /**
     * State denoting that the certificate issuance was requested and certificate issued and received successfully
     */
    data class Issued(
        val issuedAt: Instant,
        val certificate: IssuedCertificate,
    ) : AuthCodeFlowIssuance
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
 * Models a request for credential issuance
 */
sealed interface CredentialIssuanceRequest {

    val format: String
    val proof: ProofType?
    val credentialEncryptionJwk: JWK?
    val credentialResponseEncryptionAlg: JWEAlgorithm?
    val credentialResponseEncryptionMethod: EncryptionMethod?

    class MsoMdocIssuanceRequest private constructor(
        override val format: String = "mso_mdoc",
        override val proof: ProofType?,
        override val credentialEncryptionJwk: JWK?,
        override val credentialResponseEncryptionAlg: JWEAlgorithm?,
        override val credentialResponseEncryptionMethod: EncryptionMethod?,
        val doctype: String,
        val claims: Map<Namespace, Map<ClaimName, CredentialSupportedObject.MsoMdocCredentialCredentialSupportedObject.ClaimObject>>?,
    ) : CredentialIssuanceRequest {

        companion object {
            operator fun invoke(
                proof: ProofType?,
                credentialEncryptionJwk: JWK?,
                credentialResponseEncryptionAlg: JWEAlgorithm?,
                credentialResponseEncryptionMethod: EncryptionMethod?,
                doctype: String,
                claims: Map<Namespace, Map<ClaimName, CredentialSupportedObject.MsoMdocCredentialCredentialSupportedObject.ClaimObject>>?,
            ): MsoMdocIssuanceRequest {
                var encryptionMethod = credentialResponseEncryptionMethod
                if (credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null) {
                    encryptionMethod = EncryptionMethod.A256GCM
                } else if (credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null) {
                    error("Credential response encryption algorithm must be specified if Credential response encryption method is provided")
                }

                return MsoMdocIssuanceRequest(
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
 * Interface that defines the state transitions that are happening in a credential issuance process that follows
 * the Authorization Code Flow of OpenId4VCI specification.
 */
interface AuthorizationCodeFlowIssuer {
    suspend fun placePushedAuthorizationRequest(
        credentials: List<OfferedCredential>,
        issuerState: String?,
    ): Result<AuthCodeFlowIssuance.ParRequested>

    suspend fun AuthCodeFlowIssuance.ParRequested.authorize(authorizationCode: String): Result<AuthCodeFlowIssuance.Authorized>

    suspend fun AuthCodeFlowIssuance.Authorized.placeAccessTokenRequest(): Result<AuthCodeFlowIssuance.AccessTokenRetrieved>

    suspend fun AuthCodeFlowIssuance.AccessTokenRetrieved.issueCredential(): Result<AuthCodeFlowIssuance.Issued>

    companion object {
        fun make(authorizer: IssuanceAuthorizer) = DefaultAuthorizationCodeFlowIssuer(authorizer)
        fun ktor(
            authorizationServerMetadata: AuthorizationServerMetadata,
            config: WalletOpenId4VCIConfig,
        ) = DefaultAuthorizationCodeFlowIssuer(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
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
            authorizationServerMetadata: AuthorizationServerMetadata,
            config: WalletOpenId4VCIConfig,
        ) = DefaultPreAuthorizedCodeFlowIssuer(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authorizationServerMetadata,
                config = config,
            ),
        )
    }
}
