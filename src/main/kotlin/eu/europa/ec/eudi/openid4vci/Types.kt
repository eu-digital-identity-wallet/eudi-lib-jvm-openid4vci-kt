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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.MissingRequiredRequestEncryptionSpecification
import eu.europa.ec.eudi.openid4vci.internal.ensureNotNull
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant

const val FORMAT_MSO_MDOC = "mso_mdoc"
const val FORMAT_SD_JWT_VC = "dc+sd-jwt"
const val FORMAT_W3C_JSONLD_DATA_INTEGRITY = "ldp_vc"
const val FORMAT_W3C_JSONLD_SIGNED_JWT = "jwt_vc_json-ld"
const val FORMAT_W3C_SIGNED_JWT = "jwt_vc_json"

/**
 * A [URI] that strictly uses the 'https' protocol.
 */
@JvmInline
value class HttpsUrl private constructor(val value: URL) {

    override fun toString(): String = value.toString()

    companion object {

        /**
         * Parses the provided [value] as a [URI] and tries creates a new [HttpsUrl].
         */
        operator fun invoke(value: String): Result<HttpsUrl> = runCatching {
            val uri = URI.create(value)
            require(uri.scheme.contentEquals("https", true)) { "URL must use https protocol" }
            HttpsUrl(uri.toURL())
        }
    }
}

@JvmInline
@Serializable
value class CredentialConfigurationIdentifier(val value: String) {
    init {
        require(value.isNotEmpty()) { "value cannot be empty" }
    }
    override fun toString(): String = value
}

@JvmInline
@Serializable
value class CredentialIdentifier(val value: String) {
    init {
        require(value.isNotEmpty()) { "value cannot be empty" }
    }
    override fun toString(): String = value
}

/**
 * Domain object to describe a valid PKCE verifier
 */
data class PKCEVerifier(
    val codeVerifier: String,
    val codeVerifierMethod: String,
) : java.io.Serializable {
    init {
        require(codeVerifier.isNotEmpty()) { "Code verifier must not be empty" }
        require(codeVerifierMethod.isNotEmpty()) { "Code verifier method must not be empty" }
    }
}

interface CanExpire {
    val expiresIn: Duration?

    fun isExpired(issued: Instant, at: Instant): Boolean {
        require(issued.isBefore(at) || issued == at) { "At should be after or equal to $issued" }
        val expiresIn = expiresIn
        return if (expiresIn != null) {
            val expiration = issued.plusSeconds(expiresIn.toSeconds())
            !expiration.isAfter(at)
        } else false
    }
}

/**
 * Domain object to describe a valid issuance access token
 *
 * [Bearer] is the usual bearer access token
 * [DPoP] is an access token that must be used with a DPoP JWT
 */
sealed interface AccessToken : CanExpire, java.io.Serializable {

    val accessToken: String

    data class Bearer(override val accessToken: String, override val expiresIn: Duration?) : AccessToken {
        init {
            requireNotEmpty(accessToken)
            if (expiresIn != null) {
                require(!expiresIn.isNegative) { "Expires In should be positive" }
            }
        }
    }

    data class DPoP(override val accessToken: String, override val expiresIn: Duration?) : AccessToken {
        init {
            requireNotEmpty(accessToken)
            if (expiresIn != null) {
                require(!expiresIn.isNegative) { "Expires In should be positive" }
            }
        }
    }

    companion object {
        operator fun invoke(accessToken: String, expiresInSec: Long?, useDPoP: Boolean): AccessToken {
            requireNotEmpty(accessToken)
            val expiresIn = expiresInSec?.let { Duration.ofSeconds(it) }
            return if (useDPoP) DPoP(accessToken, expiresIn)
            else Bearer(accessToken, expiresIn)
        }

        private fun requireNotEmpty(accessToken: String) {
            require(accessToken.isNotEmpty()) { "Access Token must not be empty" }
        }
    }
}

@JvmInline
value class RefreshToken(val refreshToken: String) : java.io.Serializable {
    init {
        require(refreshToken.isNotEmpty()) { "Refresh Token must not be empty" }
    }
    override fun toString(): String = refreshToken
}

/**
 * Authorization code to be exchanged with an access token
 */
@JvmInline
value class AuthorizationCode(val code: String) {
    init {
        require(code.isNotEmpty()) { "Authorization code must not be empty" }
    }
    override fun toString(): String = code
}

/**
 * An identifier of a Deferred Issuance transaction.
 *
 * @param value The identifier's value
 */
@JvmInline
value class TransactionId(val value: String) {
    init {
        value.requireNotEmpty()
    }
    override fun toString(): String = value
}

/**
 * An identifier to be used in notification endpoint of issuer.
 *
 * @param value The identifier's value
 */
@JvmInline
value class NotificationId(val value: String) {
    init {
        value.requireNotEmpty()
    }
    override fun toString(): String = value
}

/**
 * A sealed hierarchy that defines the different ways of including a PUB key
 * in a JWT Proof
 */
sealed interface JwtBindingKey {

    /**
     * A JWK biding key
     */
    @JvmInline
    value class Jwk(
        val jwk: JWK,
    ) : JwtBindingKey {
        init {
            require(!jwk.isPrivate) { "Binding key of type Jwk must contain a public key" }
        }
    }

    /**
     * A Did biding key
     */
    @JvmInline
    value class Did(
        val identity: String,
    ) : JwtBindingKey

    /**
     * An X509 biding key
     */
    @JvmInline
    value class X509(
        val chain: List<X509Certificate>,
    ) : JwtBindingKey {
        init {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty" }
        }
    }
}

/**
 * Represents the specifications and parameters required for encryption. Used for encrypting issuance requests or for communicating
 * to issuers the encryption parameters by which expected issuance responses should be encrypted by.
 *
 * This class is designed to encapsulate encryption-related configurations,
 * including the key, encryption method, and an optional compression algorithm.
 * It validates the provided key and algorithm for compatibility with the
 * encryption operation and ensures that they adhere to the expected asymmetric
 * encryption standards.
 *
 * @property recipientKey The JSON Web Key (JWK) used for encryption, representing the cryptographic key.
 * @property encryptionMethod The encryption method specifying the algorithm for payload encryption.
 * @property compressionAlgorithm An optional compression algorithm to apply before encryption.
 * @property encryptionKeyAlgorithm The derived encryption key algorithm from the JWK's algorithm property, expected to be of type JWEAlgorithm.
 *
 * @throws IllegalArgumentException If the key use is not intended for encryption, if the key does not contain an algorithm,
 * or the algorithm is incompatible with the key or encryption process.
 */
data class EncryptionSpec(
    val recipientKey: JWK,
    val encryptionMethod: EncryptionMethod,
    val compressionAlgorithm: CompressionAlgorithm? = null,
) : java.io.Serializable {

    val algorithm: JWEAlgorithm
        get() = JWEAlgorithm.parse(recipientKey.algorithm.name)

    init {
        // Validate key is for encryption operation
        val keyUse: KeyUse? = recipientKey.keyUse
        if (keyUse != null) {
            require(keyUse == KeyUse.ENCRYPTION) {
                "Provided key use is not encryption"
            }
        }
        val keyAlgorithm = recipientKey.algorithm
        requireNotNull(keyAlgorithm) {
            "Provided key does not contain an algorithm"
        }
        // Validate algorithm provided is for asymmetric encryption
        require(JWEAlgorithm.Family.ASYMMETRIC.contains(keyAlgorithm)) {
            "Provided encryption algorithm is not an asymmetric encryption algorithm"
        }
        // Validate algorithm matches key
        require(recipientKey.keyType == KeyType.forAlgorithm(keyAlgorithm)) {
            "Encryption key and encryption algorithm do not match"
        }
    }
}

/**
 * Represents the encryption specifications for an issuance process, encompassing request and response encryption.
 *
 * This class is used to define the encryption configuration for:
 * - The issuance request, specifying the parameters required to encrypt the request sent to the issuer.
 * - The issuance response, specifying the expected parameters of encrypted responses received from the issuer.
 *
 * If according to wallet configuration and issuer capabilities, response encryption is feasible, it will be used to
 * request encrypted responses from issuer. In this case the request must be also encrypted, so it is mandatory to have
 * a request encryption specification.
 *
 * Each encryption specification leverages the `EncryptionSpec` class to ensure compatibility and secure encryption using standards
 * such as JWKs and JWE algorithms.
 *
 * @property requestEncryptionSpec The encryption specification for securing issuance requests sent to the issuer.
 * @property responseEncryptionSpec The encryption specification for securing issuance responses returned by the issuer.
 *
 * @throws MissingRequiredRequestEncryptionSpecification Thrown when a response encryption specification is provided
 * but request encryption specification is missing.
 */
data class ExchangeEncryptionSpecification(
    val requestEncryptionSpec: EncryptionSpec?,
    val responseEncryptionSpec: EncryptionSpec?,
) {
    init {
        if (responseEncryptionSpec != null) {
            ensureNotNull(requestEncryptionSpec) {
                MissingRequiredRequestEncryptionSpecification()
            }
        }
    }
}

/**
 * A credential identified as a scope
 */
@JvmInline
value class Scope(val value: String) {
    init {
        require(value.isNotEmpty()) { "Scope value cannot be empty" }
    }
    override fun toString(): String = value
}

typealias CIAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata

val CIAuthorizationServerMetadata.challengeEndpointURI: URI?
    get() = JSONObjectUtils.getURI(customParameters, AttestationBasedClientAuthenticationSpec.CHALLENGE_ENDPOINT)

val CIAuthorizationServerMetadata.clientAttestationJWSAlgs: List<JWSAlgorithm>?
    get() = JSONObjectUtils.getStringList(
        customParameters,
        AttestationBasedClientAuthenticationSpec.ATTESTATION_JWT_SIGNING_ALGORITHMS_SUPPORTED,
    )
        ?.mapNotNull { JWSAlgorithm.parse(it) }

val CIAuthorizationServerMetadata.clientAttestationPOPJWSAlgs: List<JWSAlgorithm>?
    get() = JSONObjectUtils.getStringList(
        customParameters,
        AttestationBasedClientAuthenticationSpec.ATTESTATION_POP_JWT_SIGNING_ALGORITHMS_SUPPORTED,
    )
        ?.mapNotNull { JWSAlgorithm.parse(it) }

@JvmInline
value class CoseAlgorithm(val value: Int) {
    companion object {
        val ES256 = CoseAlgorithm(-7)
        val ES384 = CoseAlgorithm(-35)
        val ES512 = CoseAlgorithm(-36)

        internal val Names: Map<CoseAlgorithm, String> = mapOf(
            ES256 to "ES256",
            ES384 to "ES384",
            ES512 to "ES512",
        )
    }
}

internal fun CoseAlgorithm.name(): String? = CoseAlgorithm.Names[this]

/**
 * Nonce (single use) value provided either by the Authorization or Resource server.
 */
@JvmInline
@Serializable
value class Nonce(val value: String) {
    init {
        require(value.isNotEmpty()) { "Nonce value cannot be empty" }
    }
    override fun toString(): String = value
}

/**
 * Checks if a [X509Certificate] chain is trusted or not.
 */
fun interface CertificateChainTrust {
    suspend fun isTrusted(chain: List<X509Certificate>): Boolean
}

/**
 * Mechanism a Wallet can establish trust with a JWT Issuer.
 */
sealed interface IssuerTrust {

    data class ByPublicKey(val jwk: JWK) : IssuerTrust {
        init {
            require(!jwk.isPrivate) { "Only public JWKs are supported" }
        }
    }

    data class ByCertificateChain(val certificateChainTrust: CertificateChainTrust) : IssuerTrust
}

private fun String.requireNotEmpty() {
    require(isNotEmpty()) { "Value cannot be empty" }
}

/**
 * Unique identifier for a JWT.
 */
@JvmInline
@Serializable
value class JwtId(val value: String) {
    init {
        require(value.isNotBlank()) { "value cannot be blank" }
    }
    override fun toString(): String = value
}
