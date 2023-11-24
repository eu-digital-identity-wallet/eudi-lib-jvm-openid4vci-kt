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

import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialOfferRequestResolver
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialMetadata
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.io.Serializable
import kotlin.time.Duration

/**
 * A Credential Offer.
 */
data class CredentialOffer(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val credentialIssuerMetadata: CredentialIssuerMetadata,
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
    val credentials: List<CredentialMetadata>,
    val grants: Grants? = null,
) : Serializable {
    init {
        require(credentials.isNotEmpty()) { "credentials must not be empty" }
    }
}

/**
 * The Id of a Credential Issuer. An [HttpsUrl] that has no fragment or query parameters.
 */
@JvmInline
value class CredentialIssuerId private constructor(val value: HttpsUrl) {

    override fun toString(): String =
        value.value.toString()

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerId].
         */
        operator fun invoke(value: String): Result<CredentialIssuerId> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.fragment.isNullOrBlank()) { "CredentialIssuerId must not have a fragment" }
                    require(it.value.query.isNullOrBlank()) { "CredentialIssuerId must not have query parameters " }
                    CredentialIssuerId(it)
                }
    }
}

/**
 * The Grant Types a Credential Issuer can process for a Credential Offer.
 */
sealed interface Grants : Serializable {

    /**
     * Data for an Authorization Code Grant. [issuerState], if provided, must not be blank.
     */
    data class AuthorizationCode(
        val issuerState: String? = null,
    ) : Grants {
        init {
            issuerState?.let {
                require(issuerState.isNotBlank()) { "issuerState cannot be blank" }
            }
        }
    }

    /**
     * Data for a Pre-Authorized Code Grant. [preAuthorizedCode] must not be blank.
     */
    data class PreAuthorizedCode(
        val preAuthorizedCode: String,
        val pinRequired: Boolean = false,
        val interval: Duration,
    ) : Grants {
        init {
            require(preAuthorizedCode.isNotBlank()) { "preAuthorizedCode cannot be blank" }
            require(interval.isPositive()) { "interval cannot be negative or zero" }
        }
    }

    /**
     * Data for either an Authorization Code Grant or a Pre-Authorized Code Grant.
     */
    data class Both(
        val authorizationCode: AuthorizationCode,
        val preAuthorizedCode: PreAuthorizedCode,
    ) : Grants
}

/**
 * Credential Offer request.
 */
sealed interface CredentialOfferRequest : Serializable {

    /**
     * A Credential Offer request that was passed using the 'credential_offer' query parameter.
     */
    @JvmInline
    value class PassByValue(val value: String) : CredentialOfferRequest

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
    data class NonParseableCredentialOffer(val reason: Throwable) : CredentialOfferRequestError

    /**
     * The metadata of the Credential Issuer could not be resolved.
     */
    data class UnableToResolveCredentialIssuerMetadata(val reason: Throwable) : CredentialOfferRequestError

    /**
     * The metadata of the Authorization Server could not be resolved.
     */
    data class UnableToResolveAuthorizationServerMetadata(val reason: Throwable) : CredentialOfferRequestError

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
 * An exception indicating a [CredentialOfferRequestError] occurred while trying to validate or resolve a [CredentialOfferRequest].
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

    companion object {

        /**
         * Creates a new [CredentialOfferRequestResolver].
         */
        operator fun invoke(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): CredentialOfferRequestResolver =
            DefaultCredentialOfferRequestResolver(
                ioCoroutineDispatcher = ioCoroutineDispatcher,
                ktorHttpClientFactory = ktorHttpClientFactory,
            )
    }
}
