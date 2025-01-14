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
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialIssuerMetadataResolver
import java.io.Serializable
import java.net.URI
import java.net.URL

sealed interface CredentialResponseEncryption : Serializable {
    data object NotSupported : CredentialResponseEncryption {
        private fun readResolve(): Any = NotSupported
    }

    data class SupportedNotRequired(
        val encryptionAlgorithmsAndMethods: SupportedEncryptionAlgorithmsAndMethods,
    ) : CredentialResponseEncryption

    data class Required(
        val encryptionAlgorithmsAndMethods: SupportedEncryptionAlgorithmsAndMethods,
    ) : CredentialResponseEncryption
}

data class SupportedEncryptionAlgorithmsAndMethods(
    val algorithms: List<JWEAlgorithm>,
    val encryptionMethods: List<EncryptionMethod>,
) {
    init {
        require(encryptionMethods.isNotEmpty()) { "encryptionMethodsSupported cannot be empty" }

        if (algorithms.isEmpty()) {
            throw CredentialIssuerMetadataValidationError.CredentialResponseEncryptionAlgorithmsRequired()
        }
        val allAreAsymmetricAlgorithms = algorithms.all {
            JWEAlgorithm.Family.ASYMMETRIC.contains(it)
        }
        if (!allAreAsymmetricAlgorithms) {
            throw CredentialIssuerMetadataValidationError.CredentialResponseAsymmetricEncryptionAlgorithmsRequired()
        }
    }
}

sealed interface BatchCredentialIssuance : Serializable {
    data object NotSupported : BatchCredentialIssuance {
        private fun readResolve(): Any = NotSupported
    }

    data class Supported(val batchSize: Int) : BatchCredentialIssuance {
        init {
            require(batchSize > 0) { "batchSize must be greater than 0" }
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
    val deferredCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val notificationEndpoint: CredentialIssuerEndpoint? = null,
    val credentialResponseEncryption: CredentialResponseEncryption = CredentialResponseEncryption.NotSupported,
    val batchCredentialIssuance: BatchCredentialIssuance = BatchCredentialIssuance.NotSupported,
    val credentialConfigurationsSupported: Map<CredentialConfigurationIdentifier, CredentialConfiguration>,
    val display: List<Display> = emptyList(),
) : Serializable {

    init {
        require(credentialConfigurationsSupported.isNotEmpty()) { "credentialConfigurationsSupported must not be empty" }
    }

    inline fun <reified T : CredentialConfiguration> findByFormat(predicate: (T) -> Boolean): Map<CredentialConfigurationIdentifier, T> {
        return credentialConfigurationsSupported.mapNotNull { (k, v) -> if (v is T && predicate(v)) k to v else null }.toMap()
    }

    /**
     * The display properties of the Credential Issuer.
     */
    data class Display(
        val name: String? = null,
        val locale: String? = null,
        val logo: Logo? = null,
    ) : Serializable {
        /**
         * Logo information.
         */
        data class Logo(
            val uri: URI? = null,
            val alternativeText: String? = null,
        ) : Serializable
    }
}

fun CredentialIssuerMetadata.findMsoMdoc(docType: String): MsoMdocCredential? =
    findByFormat<MsoMdocCredential> { it.docType == docType }.values.firstOrNull()

/**
 * An endpoint of a Credential Issuer. It's an [HttpsUrl] that must not have a fragment.
 */
@JvmInline
value class CredentialIssuerEndpoint(val value: URL) {

    init {
        require(value.toURI().fragment.isNullOrBlank()) { "CredentialIssuerEndpoint must not have a fragment" }
    }

    override fun toString(): String = value.toString()

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerEndpoint].
         */
        operator fun invoke(value: String): Result<CredentialIssuerEndpoint> =
            HttpsUrl(value).mapCatching { CredentialIssuerEndpoint(it.value) }
    }
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
     * The URL of the Deferred Credential Endpoint is not valid.
     */
    class InvalidDeferredCredentialEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * The URL of the Notification Endpoint is not valid.
     */
    class InvalidNotificationEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * Credential Encryption Algorithms are required.
     */
    class CredentialResponseEncryptionAlgorithmsRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential ResponseEncryption Algorithms Required"))

    /**
     * Credential Encryption Algorithms must be of asymmetric encryption family.
     */
    class CredentialResponseAsymmetricEncryptionAlgorithmsRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Asymmetric ResponseEncryption Algorithms Required"))

    /**
     * The supported Credentials not valid.
     */
    class InvalidCredentialsSupported(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * Supported Credentials are required.
     */
    class CredentialsSupportedRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credentials Supported Required"))

    class InvalidBatchSize :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("batch_size should be greater than zero"))
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
        ): CredentialIssuerMetadataResolver = CredentialIssuerMetadataResolver { issuerId ->
            ktorHttpClientFactory.invoke().use { httpClient ->
                val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
                resolver.resolve(issuerId)
            }
        }
    }
}
