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

import io.ktor.http.*
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
            }.getOrElse {
                throw CredentialOfferRequestValidationError.NonParsableCredentialOfferEndpointUrl(it).toException()
            }

            val parameters = builder.parameters
            val maybeByValue = parameters["credential_offer"]
            val maybeByReference = parameters["credential_offer_uri"]

            when {
                !maybeByValue.isNullOrBlank() && !maybeByReference.isNullOrBlank() ->
                    throw CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri.toException()

                !maybeByValue.isNullOrBlank() -> PassByValue(maybeByValue)

                !maybeByReference.isNullOrBlank() -> HttpsUrl(maybeByReference)
                    .map { PassByReference(it) }
                    .getOrElse {
                        throw CredentialOfferRequestValidationError.InvalidCredentialOfferUri(it).toException()
                    }

                else -> throw CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri.toException()
            }
        }
    }
}

/**
 * Errors that can occur while trying to validate and resolve a [CredentialOfferRequest].
 */
sealed interface CredentialOfferRequestError : Serializable

/**
 * Validation error that can occur while trying to validate a [CredentialOfferRequest].
 */
sealed interface CredentialOfferRequestValidationError : CredentialOfferRequestError {

    /**
     * The Credential Offer Endpoint URL could not be parsed.
     */
    data class NonParsableCredentialOfferEndpointUrl(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The Credential Offer Endpoint URL either contained neither the 'credential_offer' nor the 'credential_offer_uri'
     * parameter or contained both of them.
     */
    object OneOfCredentialOfferOrCredentialOfferUri : CredentialOfferRequestValidationError {
        override fun toString(): String = "OneOfCredentialOfferOrCredentialOfferUri"
    }

    /**
     * The 'credentials_offer_uri' parameter contained in the Credential Offer Endpoint URL was not a valid [HttpsUrl].
     */
    data class InvalidCredentialOfferUri(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The Credential Offer object could not be parsed.
     */
    data class NonParseableCredentialOffer(val reason: Throwable) : CredentialOfferRequestValidationError

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

    /**
     * Wraps this [CredentialOfferRequestValidationError] into a [CredentialOfferRequestException].
     */
    fun toException(): CredentialOfferRequestException = CredentialOfferRequestException(this)
}

/**
 * A exception indicating a [CredentialOfferRequestError] occurred while trying to validate or resolve a [CredentialOfferRequest].
 */
data class CredentialOfferRequestException(val error: CredentialOfferRequestError) : Exception()

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
}
