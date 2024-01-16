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

import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestError.NonParsableCredentialOfferEndpointUrl
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestValidationError.InvalidCredentialOfferUri
import eu.europa.ec.eudi.openid4vci.CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri
import eu.europa.ec.eudi.openid4vci.internal.DefaultCredentialOfferRequestResolver
import eu.europa.ec.eudi.openid4vci.internal.ensureSuccess
import io.ktor.http.*
import java.io.Serializable
import kotlin.time.Duration

/**
 * The Grant Types a Credential Issuer can process for a Credential Offer.
 */
sealed interface Grants : Serializable {

    /**
     * Data for an Authorization Code Grant. [issuerState], if provided, must not be blank.
     */
    data class AuthorizationCode(
        val issuerState: String? = null,
        val authorizationServer: HttpsUrl? = null,
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
        val authorizationServer: HttpsUrl? = null,
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
 * A Credential Offer.
 */
data class CredentialOffer(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val credentialIssuerMetadata: CredentialIssuerMetadata,
    val authorizationServerMetadata: CIAuthorizationServerMetadata,
    val credentials: List<CredentialIdentifier>,
    val grants: Grants? = null,
) : Serializable {
    init {
        require(credentials.isNotEmpty()) { "credentials must not be empty" }
    }
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
            val parameters = try {
                URLBuilder(url).parameters
            } catch (t: URLParserException) {
                throw NonParsableCredentialOfferEndpointUrl(t).toException()
            }

            val maybeByValue = parameters["credential_offer"]
                ?.takeIf { it.isNotEmpty() }
                ?.let(::PassByValue)

            val maybeByReference = parameters["credential_offer_uri"]?.let {
                val offerUri = HttpsUrl(it).ensureSuccess { t -> InvalidCredentialOfferUri(t).toException() }
                PassByReference(offerUri)
            }

            fun oneOfRequired(): Nothing = throw OneOfCredentialOfferOrCredentialOfferUri.toException()
            when {
                maybeByValue != null && maybeByReference != null -> oneOfRequired()
                maybeByValue != null -> maybeByValue
                maybeByReference != null -> maybeByReference
                else -> oneOfRequired()
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
}

/**
 * Wraps this [CredentialOfferRequestError] to a [CredentialOfferRequestException].
 */
internal fun CredentialOfferRequestError.toException(): CredentialOfferRequestException =
    CredentialOfferRequestException(this)

/**
 * Validation error that can occur while trying to validate a [CredentialOfferRequest].
 */
sealed interface CredentialOfferRequestValidationError : CredentialOfferRequestError {

    /**
     * The Credential Offer Endpoint URL either contained neither the 'credential_offer' nor the 'credential_offer_uri'
     * parameter or contained both of them.
     */
    data object OneOfCredentialOfferOrCredentialOfferUri : CredentialOfferRequestValidationError {

        private fun readResolve(): Any = OneOfCredentialOfferOrCredentialOfferUri
    }

    /**
     * The 'credentials_offer_uri' parameter contained in the Credential Offer Endpoint URL was not a valid [HttpsUrl].
     */
    data class InvalidCredentialOfferUri(val reason: Throwable) : CredentialOfferRequestValidationError

    /**
     * The ID of the Credential Issuer is not valid.
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
        CredentialOfferRequest(uri).fold(onSuccess = { resolve(it) }, onFailure = { Result.failure(it) })

    /**
     * Tries to validate and resolve a [Credential Offer Request][request].
     */
    suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer>

    companion object {

        /**
         * Creates a new [CredentialOfferRequestResolver].
         */
        operator fun invoke(
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): CredentialOfferRequestResolver =
            DefaultCredentialOfferRequestResolver(
                ktorHttpClientFactory = ktorHttpClientFactory,
            )
    }
}
