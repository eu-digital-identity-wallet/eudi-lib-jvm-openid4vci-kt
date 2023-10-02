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

import java.io.Serializable

/**
 * Errors that can occur while trying to fetch and validate the metadata of a Credential Issuer.
 */
sealed interface CredentialIssuerMetadataError : Serializable {

    /**
     * Indicates that the URL used to fetch the Credential Issuer metadata is not valid.
     */
    data class InvalidCredentialIssuerMetadataUrl(val cause: Throwable) : CredentialIssuerMetadataError

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
fun interface CredentialIssuerMetadataResolver {

    /**
     * Tries to fetch and validate the metadata of a Credential Issuer.
     */
    suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata>

}
