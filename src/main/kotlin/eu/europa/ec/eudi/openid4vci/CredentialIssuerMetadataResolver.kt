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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialIssuerMetadataResolver
import eu.europa.ec.eudi.openid4vci.internal.ensure
import io.ktor.client.*
import java.io.Serializable
import java.net.URL

sealed interface CredentialRequestEncryption : Serializable {
    data object NotSupported : CredentialRequestEncryption {
        @Suppress("unused")
        private fun readResolve(): Any = NotSupported
    }

    data class SupportedNotRequired(
        val encryptionParameters: SupportedRequestEncryptionParameters,
    ) : CredentialRequestEncryption

    data class Required(
        val encryptionParameters: SupportedRequestEncryptionParameters,
    ) : CredentialRequestEncryption
}

sealed interface CredentialResponseEncryption : Serializable {
    data object NotSupported : CredentialResponseEncryption {
        @Suppress("unused")
        private fun readResolve(): Any = NotSupported
    }

    data class SupportedNotRequired(
        val encryptionParameters: SupportedResponseEncryptionParameters,
    ) : CredentialResponseEncryption

    data class Required(
        val encryptionParameters: SupportedResponseEncryptionParameters,
    ) : CredentialResponseEncryption
}

sealed interface PayloadCompression : Serializable {
    data object NotSupported : PayloadCompression {
        @Suppress("unused")
        private fun readResolve(): Any = NotSupported
    }

    data class Supported(
        val algorithms: List<CompressionAlgorithm>,
    ) : PayloadCompression {
        init {
            require(algorithms.isNotEmpty()) { "Compression algorithms must be specified" }
        }
    }

    companion object {
        operator fun invoke(algorithms: List<CompressionAlgorithm>?) = when {
            algorithms != null && algorithms.isNotEmpty() -> Supported(algorithms)
            else -> NotSupported
        }
    }
}

data class SupportedResponseEncryptionParameters(
    val algorithms: List<JWEAlgorithm>,
    val encryptionMethods: List<EncryptionMethod>,
    val payloadCompression: PayloadCompression = PayloadCompression.NotSupported,
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

data class SupportedRequestEncryptionParameters(
    val encryptionKeys: JWKSet,
    val encryptionMethods: List<EncryptionMethod>,
    val payloadCompression: PayloadCompression = PayloadCompression.NotSupported,
) {
    init {
        require(encryptionMethods.isNotEmpty()) { "encryptionMethodsSupported cannot be empty" }
        if (encryptionKeys.isEmpty()) {
            throw CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysRequired()
        }
        encryptionKeys.keys.forEach {
            ensure(it.keyID != null) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysMustHaveKeyId()
            }
            ensure(it.algorithm != null) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysMustHaveAlgorithm()
            }
            ensure(JWEAlgorithm.Family.ASYMMETRIC.contains(it.algorithm)) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysMustHaveAsymmetricAlgorithm()
            }
            ensure(!it.isPrivate) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysMustBePublic()
            }
            ensure(it.keyType == KeyType.forAlgorithm(it.algorithm)) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeyWrongKeyType()
            }
            ensure(it.keyUse == KeyUse.ENCRYPTION) {
                CredentialIssuerMetadataValidationError.CredentialRequestEncryptionKeysMustHaveEncryptionUsage()
            }
        }
    }
}

sealed interface BatchCredentialIssuance : Serializable {
    data object NotSupported : BatchCredentialIssuance {
        @Suppress("unused")
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
    val nonceEndpoint: CredentialIssuerEndpoint? = null,
    val deferredCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val notificationEndpoint: CredentialIssuerEndpoint? = null,
    val credentialRequestEncryption: CredentialRequestEncryption = CredentialRequestEncryption.NotSupported,
    val credentialResponseEncryption: CredentialResponseEncryption = CredentialResponseEncryption.NotSupported,
    val batchCredentialIssuance: BatchCredentialIssuance = BatchCredentialIssuance.NotSupported,
    val credentialConfigurationsSupported: Map<CredentialConfigurationIdentifier, CredentialConfiguration>,
    val display: List<Display> = emptyList(),
) : Serializable {

    init {
        require(credentialConfigurationsSupported.isNotEmpty()) { "credentialConfigurationsSupported must not be empty" }
    }

    inline fun <reified T : CredentialConfiguration> findByFormat(predicate: (T) -> Boolean): Map<CredentialConfigurationIdentifier, T> {
        return credentialConfigurationsSupported.mapNotNull { (k, v) -> if (v is T && predicate(v)) k to v else null }
            .toMap()
    }
}

@Suppress("unused")
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

    /**
     * Indicates the Credential Issuer does not provide signed metadata.
     */
    class MissingSignedMetadata() : CredentialIssuerMetadataError(IllegalArgumentException("missing signed_metadata"))

    /**
     * Indicates the signed metadata of the Credential Issuer are not valid.
     */
    class InvalidSignedMetadata(cause: Throwable) : CredentialIssuerMetadataError(cause)
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
     * The URL of the Nonce Endpoint is not valid.
     */
    class InvalidNonceEndpoint(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

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
     * Credential Request Encryption keys are required.
     */
    class CredentialRequestEncryptionKeysRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential Request Encryption Keys are required"))

    /**
     * Credential Request Encryption Keys must have a key id.
     */
    class CredentialRequestEncryptionKeysMustHaveKeyId :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential Request Encryption Keys must have a key id"))

    /**
     * Credential Request Encryption Keys must have algorithm.
     */
    class CredentialRequestEncryptionKeysMustHaveAlgorithm :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential Request Encryption Keys must have algorithm"))

    /**
     * Credential Request Encryption Keys must have an asymmetric algorithm.
     */
    class CredentialRequestEncryptionKeysMustHaveAsymmetricAlgorithm :
        CredentialIssuerMetadataValidationError(
            IllegalArgumentException("Provided encryption algorithm is not an asymmetric encryption algorithm"),
        )

    /**
     * A Credential Request Encryption Key type don't match with algorithm.
     */
    class CredentialRequestEncryptionKeyWrongKeyType :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Encryption key type and encryption algorithm do not match"))

    /**
     * Credential Request Encryption Keys must all be for encryption use.
     */
    class CredentialRequestEncryptionKeysMustHaveEncryptionUsage :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("All encryption keys must have use 'enc'"))

    /**
     * Credential Request Encryption Keys must be public.
     */
    class CredentialRequestEncryptionKeysMustBePublic :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credential Request Encryption Keys must be public."))

    /**
     * The supported Credentials not valid.
     */
    class InvalidCredentialsSupported(cause: Throwable) : CredentialIssuerMetadataValidationError(cause)

    /**
     * Supported Credentials are required.
     */
    class CredentialsSupportedRequired :
        CredentialIssuerMetadataValidationError(IllegalArgumentException("Credentials Supported Required"))

    /**
     * Supported Credentials are required.
     */
    class CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists :
        CredentialIssuerMetadataValidationError(
            IllegalArgumentException(
                "Issuer must specify Credential Request Encryption if Credential Response Encryption is specified",
            ),
        )

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
    suspend fun resolve(issuer: CredentialIssuerId, policy: IssuerMetadataPolicy): Result<CredentialIssuerMetadata>

    companion object {

        /**
         * Creates a new [CredentialIssuerMetadataResolver] instance.
         */
        operator fun invoke(
            httpClient: HttpClient,
        ): CredentialIssuerMetadataResolver = CredentialIssuerMetadataResolver { issuerId, policy ->
            val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
            resolver.resolve(issuerId, policy)
        }
    }
}
