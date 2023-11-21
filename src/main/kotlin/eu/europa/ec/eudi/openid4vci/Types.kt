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
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWT
import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import io.ktor.client.*
import java.net.URI
import java.security.cert.X509Certificate

/**
 * A [URI] that strictly uses the 'https' protocol.
 */
@JvmInline
value class HttpsUrl private constructor(val value: URI) {

    override fun toString(): String = value.toString()

    companion object {

        /**
         * Parses the provided [value] as a [URI] and tries creates a new [HttpsUrl].
         */
        operator fun invoke(value: String): Result<HttpsUrl> = runCatching {
            val uri = URI.create(value)
            require(uri.scheme.contentEquals("https", true)) { "URL must use https protocol" }
            HttpsUrl(uri)
        }
    }
}

/**
 * Domain object to describe a valid PKCE verifier
 */
data class PKCEVerifier(
    val codeVerifier: String,
    val codeVerifierMethod: String,
) {
    init {
        require(codeVerifier.isNotEmpty()) { "Code verifier must not be empty" }
        require(codeVerifierMethod.isNotEmpty()) { "Code verifier method must not be empty" }
    }
}

/**
 * Domain object to describe a valid issuance access token
 */
@JvmInline
value class IssuanceAccessToken(val accessToken: String) {
    init {
        require(accessToken.isNotEmpty()) { "Access Token must not be empty" }
    }
}

/**
 * Authorization code to be exchanged with an access token
 */
@JvmInline
value class AuthorizationCode(val code: String) {
    init {
        require(code.isNotEmpty()) { "Authorization code must not be empty" }
    }
}

/**
 * Pre-Authorization code to be exchanged with an access token
 */
data class PreAuthorizationCode(
    val preAuthorizedCode: String,
    val pin: String?,
) {
    init {
        require(preAuthorizedCode.isNotEmpty()) { "Pre-Authorization code must not be empty" }
    }
}

/**
 * A c_nonce related information as provided from issuance server.
 *
 * @param value The c_nonce value
 * @param expiresInSeconds  Nonce time to live in seconds.
 */
data class CNonce(
    val value: String,
    val expiresInSeconds: Long? = 5,
) {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

/**
 * An identifier of a Deferred Issuance transaction.
 *
 * @param value The identifier's value
 * @param interval The minimum amount of time in seconds to wait before using this identifier to the Deferred Credential Endpoint.
 */
data class TransactionId(
    val value: String,
    val interval: Long? = null,
) {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

/**
 * Sealed hierarchy of the proofs of possession that can be included in a credential issuance request. Proofs are used
 * to bind the issued credential to the credential requester. They contain proof of possession of a bind key that can be
 * used to cryptographically verify that the presenter of the credential is also the holder of the credential.
 */
sealed interface Proof {

    /**
     * Proof of possession is structured as signed JWT
     *
     * @param jwt The proof JWT
     */
    @JvmInline
    value class Jwt(val jwt: JWT) : Proof

    /**
     * Proof of possession is structured as a CWT
     *
     * @param cwt The proof CWT
     */
    @JvmInline
    value class Cwt(val cwt: String) : Proof
}

/**
 * A sealed hierarchy that defines the different key formats to be used in order to construct a Proof of Possession.
 */
sealed interface BindingKey {

    /**
     * A JWK biding key
     */
    data class Jwk(
        val algorithm: JWSAlgorithm,
        val jwk: JWK,
    ) : BindingKey

    /**
     * A Did biding key
     */
    data class Did(
        val identity: String,
    ) : BindingKey

    /**
     * An X509 biding key
     */
    data class X509(
        val certificateChain: List<X509Certificate>,
    ) : BindingKey {
        init {
            require(certificateChain.isNotEmpty()) { "Certificate chane cannot be empty" }
        }
    }
}

data class IssuanceResponseEncryptionSpec(
    val jwk: JWK,
    val algorithm: JWEAlgorithm,
    val encryptionMethod: EncryptionMethod,
)

/**
 * A credential identified as a scope
 */
@JvmInline
value class Scope(val value: String) {
    init {
        require(value.isNotEmpty()) { "Scope value cannot be empty" }
    }
}

typealias KtorHttpClientFactory = () -> HttpClient

typealias CIAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata
