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
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialIssuerMetadataResolver
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.io.Serializable
import java.util.*

/**
 * The metadata of a Credential Issuer.
 */
data class CredentialIssuerMetadata(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val authorizationServer: HttpsUrl = credentialIssuerIdentifier.value,
    val credentialEndpoint: CredentialIssuerEndpoint,
    val batchCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val deferredCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val credentialResponseEncryptionAlgorithmsSupported: List<JWEAlgorithm> = emptyList(),
    val credentialResponseEncryptionMethodsSupported: List<EncryptionMethod> = emptyList(),
    val requireCredentialResponseEncryption: Boolean = false,
    val credentialsSupported: List<CredentialSupported>,
    val display: List<Display> = emptyList(),
) : java.io.Serializable {
    init {
        if (requireCredentialResponseEncryption) {
            require(credentialResponseEncryptionAlgorithmsSupported.isNotEmpty()) {
                "credentialResponseEncryptionAlgorithmsSupported are required"
            }
        }
        require(credentialsSupported.isNotEmpty()) { "credentialsSupported must not be empty" }
    }

    /**
     * The display properties of the Credential Issuer.
     */
    data class Display(
        val name: String? = null,
        val locale: String? = null,
    ) : java.io.Serializable
}

/**
 * An endpoint of a Credential Issuer. It's an [HttpsUrl] that must not have a fragment.
 */
@JvmInline
value class CredentialIssuerEndpoint private constructor(val value: HttpsUrl) {

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerEndpoint].
         */
        operator fun invoke(value: String): Result<CredentialIssuerEndpoint> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.fragment.isNullOrBlank()) { "CredentialIssuerEndpoint must not have a fragment" }
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
) : java.io.Serializable {

    /**
     * Display properties of a Claim.
     */
    @kotlinx.serialization.Serializable
    data class Display(
        @SerialName("name") val name: String? = null,
        @kotlinx.serialization.Serializable(LocalSerializer::class)
        @SerialName("locale") val locale: Locale? = null,
    ) : java.io.Serializable
}

object LocalSerializer : KSerializer<Locale> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Locale", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Locale =
        Locale.forLanguageTag(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Locale) =
        encoder.encodeString(value.toString())
}

/**
 * Credentials supported by an Issuer.
 */
sealed interface CredentialSupported : Serializable {

    val scope: String?
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val cryptographicSuitesSupported: List<String>
    val proofTypesSupported: List<ProofType>
    val display: List<Display>
}

/**
 * Cryptographic Binding Methods for issued Credentials.
 */
sealed interface CryptographicBindingMethod : java.io.Serializable {

    /**
     * JWK format.
     */
    object JWK : CryptographicBindingMethod {
        private fun readResolve(): Any = JWK
        override fun toString(): String = "JWK"
    }

    /**
     * COSE Key object.
     */
    object COSE : CryptographicBindingMethod {
        private fun readResolve(): Any = COSE
        override fun toString(): String = "COSE"
    }

    /**
     * MSO.
     */
    object MSO : CryptographicBindingMethod {
        private fun readResolve(): Any = MSO
        override fun toString(): String = "MSO"
    }

    /**
     * DID method.
     */
    data class DID(
        val method: String,
    ) : CryptographicBindingMethod
}

/**
 * Proof types supported by a Credential Issuer.
 */
enum class ProofType : java.io.Serializable {
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
) : java.io.Serializable {

    /**
     * Logo information.
     */
    data class Logo(
        val url: HttpsUrl? = null,
        val alternativeText: String? = null,
    ) : java.io.Serializable
}

/**
 * Errors that can occur while trying to fetch and validate the metadata of a Credential Issuer.
 */
sealed interface CredentialIssuerMetadataError : Serializable {

    /**
     * Indicates the Credential Issuer metadata could not be fetched.
     */
    data class UnableToFetchCredentialIssuerMetadata(val cause: Throwable) : CredentialIssuerMetadataError

    /**
     * Indicates the Credential Issuer metadata could not be parsed.
     */
    data class NonParseableCredentialIssuerMetadata(val cause: Throwable) : CredentialIssuerMetadataError

    /**
     * Wraps this [CredentialIssuerMetadataError] to a [CredentialIssuerMetadataException].
     */
    fun toException(): CredentialIssuerMetadataException = CredentialIssuerMetadataException(this)

    /**
     * Wraps this [CredentialIssuerMetadataError] and throws it as a [CredentialIssuerMetadataException].
     */
    fun raise(): Nothing = throw toException()
}

/**
 * Errors that can occur while trying to to validate the metadata of a Credential Issuer.
 */
sealed interface CredentialIssuerMetadataValidationError : CredentialIssuerMetadataError {

    /**
     * The Id of the Credential Issuer is not valid.
     */
    data class InvalidCredentialIssuerId(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * The URL of the Authorization Server is not valid.
     */
    data class InvalidAuthorizationServer(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * The URL of the Credential Endpoint is not valid.
     */
    data class InvalidCredentialEndpoint(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * The URL of the Batch Credential Endpoint is not valid.
     */
    data class InvalidBatchCredentialEndpoint(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * The URL of the Deferred Credential Endpoint is not valid.
     */
    data class InvalidDeferredCredentialEndpoint(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * The supported Credential Encryption Algorithms are not valid.
     */
    data class InvalidCredentialResponseEncryptionAlgorithmsSupported(val reason: Throwable) :
        CredentialIssuerMetadataValidationError

    /**
     * The supported Credential Encryption Methods are not valid.
     */
    data class InvalidCredentialResponseEncryptionMethodsSupported(val reason: Throwable) :
        CredentialIssuerMetadataValidationError

    /**
     * Credential Encryption Algorithms are required.
     */
    object CredentialResponseEncryptionAlgorithmsRequired : CredentialIssuerMetadataValidationError {

        private fun readResolve(): Any = CredentialResponseEncryptionAlgorithmsRequired

        override fun toString(): String = "CredentialResponseEncryptionAlgorithmsRequired"
    }

    /**
     * The supported Credentials not valid.
     */
    data class InvalidCredentialsSupported(val reason: Throwable) : CredentialIssuerMetadataValidationError

    /**
     * Supported Credentials are required.
     */
    object CredentialsSupportedRequired : CredentialIssuerMetadataValidationError {

        private fun readResolve(): Any = CredentialsSupportedRequired

        override fun toString(): String = "CredentialsSupportedRequired"
    }

    /**
     * Display is not valid.
     */
    data class InvalidDisplay(val reason: Throwable) : CredentialIssuerMetadataValidationError
}

/**
 * Indicates a [CredentialOfferRequestError] occurred while trying to fetch or validate the metadata of a Credential Issuer.
 */
data class CredentialIssuerMetadataException(val error: CredentialIssuerMetadataError) : Exception()

/**
 * Service for fetching, parsing, and validating the metadata of a Credential Issuer.
 */
internal fun interface CredentialIssuerMetadataResolver {

    /**
     * Tries to fetch and validate the metadata of a Credential Issuer.
     */
    suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata>

    companion object {

        /**
         * Creates a new [CredentialIssuerMetadataResolver] instance.
         *
         * [httpGet] execution are dispatched on [ioCoroutineDispatcher].
         */
        operator fun invoke(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpGet: HttpGet<String>,
        ): CredentialIssuerMetadataResolver = DefaultCredentialIssuerMetadataResolver(ioCoroutineDispatcher, httpGet)
    }
}

typealias Namespace = String
typealias ClaimName = String
typealias MsoMdocClaims = Map<Namespace, Map<ClaimName, Claim>>
