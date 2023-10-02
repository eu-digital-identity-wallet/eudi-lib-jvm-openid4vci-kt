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
package eu.europa.ec.eudi.openid4vci.internal.credentialoffer

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialSupportedObject.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.io.Serializable
import java.net.URL

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
            ioCoroutineDispatcher: CoroutineDispatcher,
            httpGet: HttpGet<String>,
        ): CredentialIssuerMetadataResolver = DefaultCredentialIssuerMetadataResolver(ioCoroutineDispatcher, httpGet)
    }
}

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
private class DefaultCredentialIssuerMetadataResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val httpGet: HttpGet<String>,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> = runCatching {
        val credentialIssuerMetadataContent = runCatching {
            val url =
                URLBuilder(issuer.value.value.toString())
                    .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
                    .build()
                    .toURI()
                    .toURL()
            fetch(url)
        }.getOrElse { CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(it).raise() }

        val credentialIssuerMetadataObject = runCatching {
            Json.decodeFromString<CredentialIssuerMetadataObject>(credentialIssuerMetadataContent)
        }.getOrElse { CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(it).raise() }

        credentialIssuerMetadataObject.toDomain()
            .also {
                if (it.credentialIssuerIdentifier != issuer) {
                    CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId(
                        IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                    ).raise()
                }
            }
    }

    /**
     * Tries to fetch the content of the provided [url] as a [String] using the configured [httpGet] using [ioCoroutineDispatcher].
     */
    private suspend fun fetch(url: URL): String =
        withContext(ioCoroutineDispatcher + CoroutineName("/.well-known/openid-credential-issuer")) {
            httpGet.get(url).getOrThrow()
        }

    companion object {

        /**
         * Converts and validates  a [CredentialIssuerMetadataObject] as a [CredentialIssuerMetadata] instance.
         */
        private fun CredentialIssuerMetadataObject.toDomain(): CredentialIssuerMetadata {
            val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
                .getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId(it).raise() }

            val authorizationServer =
                authorizationServer
                    ?.let {
                        HttpsUrl(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidAuthorizationServer(error).raise()
                        }
                    }
                    ?: credentialIssuerIdentifier.value

            val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
                .getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialEndpoint(it).raise() }

            val batchCredentialEndpoint =
                batchCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidBatchCredentialEndpoint(error).raise()
                        }
                    }

            val deferredCredentialEndpoint =
                deferredCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidDeferredCredentialEndpoint(error).raise()
                        }
                    }

            val credentialResponseEncryptionAlgorithmsSupported = runCatching {
                credentialResponseEncryptionAlgorithmsSupported.map { JWEAlgorithm.parse(it) }
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionAlgorithmsSupported(
                    it,
                ).raise()
            }

            val credentialResponseEncryptionMethodsSupported = runCatching {
                credentialResponseEncryptionMethodsSupported.map { EncryptionMethod.parse(it) }
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionMethodsSupported(it).raise()
            }

            val requireCredentialResponseEncryption = requireCredentialResponseEncryption ?: false
            if (requireCredentialResponseEncryption && credentialResponseEncryptionAlgorithmsSupported.isEmpty()) {
                CredentialIssuerMetadataValidationError.CredentialResponseEncryptionAlgorithmsRequired.raise()
            }

            val credentialsSupported = runCatching {
                credentialsSupported.map { it.toCredentialSupportedObject() }
            }.getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialsSupported(it).raise() }
            if (credentialsSupported.isEmpty()) {
                CredentialIssuerMetadataValidationError.CredentialsSupportedRequired.raise()
            }

            val display = runCatching {
                display.map { it.toDomain() }
            }.getOrElse { CredentialIssuerMetadataValidationError.InvalidDisplay(it).raise() }

            return CredentialIssuerMetadata(
                credentialIssuerIdentifier,
                authorizationServer,
                credentialEndpoint,
                batchCredentialEndpoint,
                deferredCredentialEndpoint,
                credentialResponseEncryptionAlgorithmsSupported,
                credentialResponseEncryptionMethodsSupported,
                requireCredentialResponseEncryption,
                credentialsSupported,
                display,
            )
        }

        /**
         * Converts a [JsonObject] to a [CredentialSupportedObject].
         */
        private fun JsonObject.toCredentialSupportedObject(): CredentialSupportedObject {
            val format =
                getOrDefault("format", JsonNull).let {
                    if (it is JsonPrimitive && it.isString) {
                        it.content
                    } else {
                        throw IllegalArgumentException("'format' must be a JsonPrimitive that contains a string")
                    }
                }

            return when (format) {
                "jwt_vc_json" -> Json.decodeFromJsonElement<W3CVerifiableCredentialSignedJwtCredentialSupportedObject>(
                    this,
                )

                "jwt_vc_json-ld" -> Json.decodeFromJsonElement<W3CVerifiableCredentialJsonLdSignedJwtCredentialSupportedObject>(
                    this,
                )

                "ldp_vc" -> Json.decodeFromJsonElement<W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupportedObject>(
                    this,
                )

                "mso_mdoc" -> Json.decodeFromJsonElement<MsoMdocCredentialSupportedObject>(
                    this,
                )

                else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
            }
        }

        /**
         * Converts a [CredentialIssuerMetadataObject.DisplayObject] to a [CredentialIssuerMetadata.Display] instance.
         */
        private fun CredentialIssuerMetadataObject.DisplayObject.toDomain(): CredentialIssuerMetadata.Display =
            CredentialIssuerMetadata.Display(name, locale)
    }
}
