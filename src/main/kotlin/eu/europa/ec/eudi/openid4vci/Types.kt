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
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.AccessToken.Bearer
import eu.europa.ec.eudi.openid4vci.AccessToken.DPoP
import kotlinx.serialization.Serializable
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant

const val FORMAT_MSO_MDOC = "mso_mdoc"
const val FORMAT_SD_JWT_VC = "vc+sd-jwt"
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
}

@JvmInline
@Serializable
value class CredentialIdentifier(val value: String) {
    init {
        require(value.isNotEmpty()) { "value cannot be empty" }
    }
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

data class RefreshToken(
    val refreshToken: String,
    override val expiresIn: Duration?,
) : CanExpire, java.io.Serializable {
    init {
        require(refreshToken.isNotEmpty()) { "Refresh Token must not be empty" }
        if (expiresIn != null) {
            require(!expiresIn.isNegative) { "Expires in should be positive" }
        }
    }

    constructor(refreshToken: String, expiresInSec: Long?) :
        this(refreshToken, expiresInSec?.let { Duration.ofSeconds(it) })
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
 * A c_nonce related information as provided from issuance server.
 *
 * @param value The c_nonce value
 * @param expiresInSeconds  Nonce time to live in seconds.
 */
data class CNonce(
    val value: String,
    val expiresInSeconds: Long? = 5,
) : java.io.Serializable {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

/**
 * An identifier of a Deferred Issuance transaction.
 *
 * @param value The identifier's value
 */
@JvmInline
value class TransactionId(val value: String) {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

/**
 * An identifier to be used in notification endpoint of issuer.
 *
 * @param value The identifier's value
 */
@JvmInline
value class NotificationId(val value: String) {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

@Deprecated(
    message = "Deprecated. It will removed in a future release.",
    replaceWith = ReplaceWith("JwtBindingKey"),
)
typealias BindingKey = JwtBindingKey

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

sealed interface CwtBindingKey {

    @JvmInline
    value class CoseKey(val jwk: JWK) : CwtBindingKey {
        init {
            require(!jwk.isPrivate) { "Binding key of type Jwk must contain a public key" }
        }
    }

    /**
     * An X509 biding key
     */
    @JvmInline
    value class X509(
        val chain: List<X509Certificate>,
    ) : CwtBindingKey {
        init {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty" }
        }
    }
}

data class IssuanceResponseEncryptionSpec(
    val jwk: JWK,
    val algorithm: JWEAlgorithm,
    val encryptionMethod: EncryptionMethod,
) : java.io.Serializable {
    init {
        // Validate algorithm provided is for asymmetric encryption
        require(JWEAlgorithm.Family.ASYMMETRIC.contains(algorithm)) {
            "Provided encryption algorithm is not an asymmetric encryption algorithm"
        }
        // Validate algorithm matches key
        require(jwk.keyType == KeyType.forAlgorithm(algorithm)) {
            "Encryption key and encryption algorithm do not match"
        }
        // Validate key is for encryption operation
        require(jwk.keyUse == KeyUse.ENCRYPTION) {
            "Provided key use is not encryption"
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
}

typealias CIAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata

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

enum class Htm {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
}
