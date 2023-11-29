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
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryption.NotRequired
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialIssuerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.LocaleSerializer
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported
import kotlinx.serialization.SerialName
import java.io.Serializable
import java.util.*

sealed interface CredentialResponseEncryption : Serializable {
    data object NotRequired : CredentialResponseEncryption {
        private fun readResolve(): Any = NotRequired
    }

    data class Required(
        val algorithmsSupported: List<JWEAlgorithm>,
        val encryptionMethodsSupported: List<EncryptionMethod>,
    ) : CredentialResponseEncryption {
        init {
            require(algorithmsSupported.isNotEmpty()) { "algorithmsSupported cannot be empty" }
            require(encryptionMethodsSupported.isNotEmpty()) { "encryptionMethodsSupported cannot be empty" }
        }
    }
}

/**
 * The metadata of a Credential Issuer.
 */
data class CredentialIssuerMetadata(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val authorizationServers: List<HttpsUrl> = listOf(credentialIssuerIdentifier.value),
    val credentialEndpoint: CredentialIssuerEndpoint,
    val batchCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val deferredCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val credentialResponseEncryption: CredentialResponseEncryption = NotRequired,
    val credentialIdentifiersSupported: Boolean = false,
    val credentialsSupported: Map<CredentialIdentifier, CredentialSupported>,
    val display: List<Display> = emptyList(),
) : Serializable {

    init {
        require(credentialsSupported.isNotEmpty()) { "credentialsSupported must not be empty" }
    }

    /**
     * The display properties of the Credential Issuer.
     */
    data class Display(
        val name: String? = null,
        val locale: String? = null,
    ) : Serializable
}

/**
 * An endpoint of a Credential Issuer. It's an [HttpsUrl] that must not have a fragment.
 */
@JvmInline
value class CredentialIssuerEndpoint private constructor(val value: HttpsUrl) {

    override fun toString(): String = value.toString()

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerEndpoint].
         */
        operator fun invoke(value: String): Result<CredentialIssuerEndpoint> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.toURI().fragment.isNullOrBlank()) { "CredentialIssuerEndpoint must not have a fragment" }
                    CredentialIssuerEndpoint(it)
                }
    }
}

/**
 * The details of a Claim.
 */
@kotlinx.serialization.Serializable
data class Claim(
    @SerialName("mandatory") val mandatory: Boolean? = false,
    @SerialName("value_type") val valueType: String? = null,
    @SerialName("display") val display: List<Display> = emptyList(),
) : Serializable {

    /**
     * Display properties of a Claim.
     */
    @kotlinx.serialization.Serializable
    data class Display(
        @SerialName("name") val name: String? = null,
        @kotlinx.serialization.Serializable(LocaleSerializer::class)
        @SerialName("locale") val locale: Locale? = null,
    ) : Serializable
}

/**
 * Cryptographic Binding Methods for issued Credentials.
 */
sealed interface CryptographicBindingMethod : Serializable {

    /**
     * JWK format.
     */
    data object JWK : CryptographicBindingMethod {
        private fun readResolve(): Any = JWK
    }

    /**
     * COSE Key object.
     */
    data object COSE : CryptographicBindingMethod {
        private fun readResolve(): Any = COSE
    }

    /**
     * MSO.
     */
    data object MSO : CryptographicBindingMethod {
        private fun readResolve(): Any = MSO
    }

    /**
     * DID method.
     */
    data class DID(val method: String) : CryptographicBindingMethod
}

/**
 * Proof types supported by a Credential Issuer.
 */
enum class ProofType : Serializable {
    JWT,
    CWT,
}

typealias CssColor = String

/**
 * Display properties of a supported credential type for a certain language.
 */
data class Display(
    val name: String,
    val locale: Locale? = null,
    val logo: Logo? = null,
    val description: String? = null,
    val backgroundColor: CssColor? = null,
    val textColor: CssColor? = null,
) : Serializable {

    /**
     * Logo information.
     */
    data class Logo(
        val url: HttpsUrl? = null,
        val alternativeText: String? = null,
    ) : Serializable
}

/**
 * Errors that can occur while trying to fetch and validate the metadata of a Credential Issuer.
 */
sealed class CredentialIssuerMetadataError(cause: Throwable) : Throwable(cause), Serializable {

    /**
     * Indicates the Credential Issuer metadata could not be fetched.
     */
    class UnableToFetchCredentialIssuerMetadata(cause: Throwable) : CredentialIssuerMetadataError(cause)

    /**
     * Indicates the Credential Issuer metadata could not be parsed.
     */
    class NonParseableCredentialIssuerMetadata(cause: Throwable) : CredentialIssuerMetadataError(cause)
}

/**
 * Errors that can occur while trying to validate the metadata of a Credential Issuer.
 */
sealed class CredentialIssuerMetadataValidationError(cause: Throwable) : CredentialIssuerMetadataError(cause) {

    /**
     * The Id of the Credential Issuer is not valid.
     */
    class InvalidCredentialIssuerId(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * The URL of the Authorization Server is not valid.
     */
    class InvalidAuthorizationServer(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * The URL of the Credential Endpoint is not valid.
     */
    class InvalidCredentialEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * The URL of the Batch Credential Endpoint is not valid.
     */
    class InvalidBatchCredentialEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * The URL of the Deferred Credential Endpoint is not valid.
     */
    class InvalidDeferredCredentialEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * Credential Encryption Algorithms are required.
     */
    object CredentialResponseEncryptionAlgorithmsRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential ResponseEncryption Algorithms Required")) {

        private fun readResolve(): Any = CredentialResponseEncryptionAlgorithmsRequired
    }

    /**
     * Credential Encryption Algorithms must be of asymmetric encryption family.
     */
    object CredentialResponseAsymmetricEncryptionAlgorithmsRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Asymmetric ResponseEncryption Algorithms Required")) {

        private fun readResolve(): Any = CredentialResponseAsymmetricEncryptionAlgorithmsRequired
    }

    /**
     * The supported Credentials not valid.
     */
    class InvalidCredentialsSupported(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * Supported Credentials are required.
     */
    object CredentialsSupportedRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credentials Supported Required")) {

        private fun readResolve(): Any = CredentialsSupportedRequired
    }
}

/**
 * Service for fetching, parsing, and validating the metadata of a Credential Issuer.
 */
fun interface CredentialIssuerMetadataResolver {

    /**
     * Tries to fetch and validate the metadata of a Credential Issuer.
     */
    suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata>

    companion object {

        /**
         * Creates a new [CredentialIssuerMetadataResolver] instance.
         */
        operator fun invoke(
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): CredentialIssuerMetadataResolver =
            DefaultCredentialIssuerMetadataResolver(
                ktorHttpClientFactory = ktorHttpClientFactory,
            )
    }
}

typealias Namespace = String
typealias ClaimName = String
typealias MsoMdocClaims = Map<Namespace, Map<ClaimName, Claim>>
