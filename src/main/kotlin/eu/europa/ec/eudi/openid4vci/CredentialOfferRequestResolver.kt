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

import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialOfferRequestResolver
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.io.Serializable

/**
 * Credential Offer request.
 */
sealed interface CredentialOfferRequest : Serializable {

    /**
     * A Credential Offer request that was passed using the 'credential_offer' query parameter.
     */
    @JvmInline
    value class PassByValue(val value: JsonString) : CredentialOfferRequest

    /**
     * A Credential Offer request that must be resolved using the 'credential_offer_uri' parameter.
     */
    @JvmInline
    value class PassByReference(val value: HttpsUrl) : CredentialOfferRequest

    companion object {

        /**
         * Parses a URL to a [CredentialOfferRequest].
         *
         * In case of [Result.Failure] a [CredentialOfferRequestException] is thrown.
         */
        operator fun invoke(url: String): Result<CredentialOfferRequest> = runCatching {
            val builder = runCatching {
                URLBuilder(url)
            }.getOrElse { CredentialOfferRequestError.NonParsableCredentialOfferEndpointUrl(it).raise() }

            val parameters = builder.parameters
            val maybeByValue = parameters["credential_offer"]
            val maybeByReference = parameters["credential_offer_uri"]

            when {
                !maybeByValue.isNullOrBlank() && !maybeByReference.isNullOrBlank() ->
                    CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri.raise()

                !maybeByValue.isNullOrBlank() -> PassByValue(maybeByValue)

                !maybeByReference.isNullOrBlank() -> HttpsUrl(maybeByReference)
                    .map { PassByReference(it) }
                    .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialOfferUri(it).raise() }

                else -> CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri.raise()
            }
        }
    }
}

/**
 * Errors that can occur while trying to validate and resolve a [CredentialOfferRequest].
 */
sealed interface CredentialOfferRequestError : Serializable {

    /**
     * The Credential Offer Endpoint URL could not be parsed.
     */
    data class NonParsableCredentialOfferEndpointUrl(val reason: Throwable) : CredentialOfferRequestError

    /**
     * The Credential Offer object could not be fetched.
     */
    data class UnableToFetchCredentialOffer(val reason: Throwable) : CredentialOfferRequestError

    /**
     * The Credential Offer object could not be parsed.
     */
    data class NonParseableCredentialOffer(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The metadata of the Credential Issuer could not be resolved.
     */
    data class UnableToResolveCredentialIssuerMetadata(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * Wraps this [CredentialOfferRequestError] to a [CredentialOfferRequestException].
     */
    fun toException(): CredentialOfferRequestException = CredentialOfferRequestException(this)

    /**
     * Wraps this [CredentialOfferRequestError] to a [CredentialOfferRequestException] and throws it.
     */
    fun raise(): Nothing = throw toException()
}

/**
 * Validation error that can occur while trying to validate a [CredentialOfferRequest].
 */
sealed interface CredentialOfferRequestValidationError : CredentialOfferRequestError {

    /**
     * The Credential Offer Endpoint URL either contained neither the 'credential_offer' nor the 'credential_offer_uri'
     * parameter or contained both of them.
     */
    object OneOfCredentialOfferOrCredentialOfferUri : CredentialOfferRequestValidationError {

        private fun readResolve(): Any = OneOfCredentialOfferOrCredentialOfferUri

        override fun toString(): String = "OneOfCredentialOfferOrCredentialOfferUri"
    }

    /**
     * The 'credentials_offer_uri' parameter contained in the Credential Offer Endpoint URL was not a valid [HttpsUrl].
     */
    data class InvalidCredentialOfferUri(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The Id of the Credential Issuer is not valid.
     */
    data class InvalidCredentialIssuerId(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The Credentials of a Credential Offer are not valid.
     */
    data class InvalidCredentials(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The Grants of a Credential Offer are not valid.
     */
    data class InvalidGrants(val reason: Throwable) : CredentialOfferRequestValidationError
}

/**
 * A exception indicating a [CredentialOfferRequestError] occurred while trying to validate or resolve a [CredentialOfferRequest].
 */
data class CredentialOfferRequestException(val error: CredentialOfferRequestError) : Exception()

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
 * Service for parsing, extracting and validating a [CredentialOfferRequest].
 */
fun interface CredentialOfferRequestResolver {

    /**
     * Tries to parse a Credential Offer Endpoint [URL][uri], extract and validate a Credential Offer Request.
     */
    suspend fun resolve(uri: String): Result<CredentialOffer> =
        CredentialOfferRequest(uri)
            .fold(
                { resolve(it) },
                { Result.failure(it) },
            )

    /**
     * Tries to validate and resolve a [Credential Offer Request][request].
     */
    suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer>

    companion object {

        /**
         * Creates a new [CredentialOfferRequestResolver].
         */
        operator fun invoke(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpGet: HttpGet<String>,
        ): CredentialOfferRequestResolver = DefaultCredentialOfferRequestResolver(ioCoroutineDispatcher, httpGet)
    }
}
