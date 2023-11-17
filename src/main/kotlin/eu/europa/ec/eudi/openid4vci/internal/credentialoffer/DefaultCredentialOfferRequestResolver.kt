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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.formats.*
import eu.europa.ec.eudi.openid4vci.formats.CredentialMetadata
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import kotlin.time.Duration.Companion.seconds

/**
 * A default implementation for [CredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher,
    private val httpGet: HttpGet<String>,
) : CredentialOfferRequestResolver {

    private val credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(ioCoroutineDispatcher, httpGet)
    private val authorizationServerMetadataResolver =
        AuthorizationServerMetadataResolver(ioCoroutineDispatcher, httpGet)

    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatching {
            val credentialOfferRequestObjectString: String = when (request) {
                is CredentialOfferRequest.PassByValue -> request.value
                is CredentialOfferRequest.PassByReference ->
                    withContext(ioCoroutineDispatcher + CoroutineName("credential-offer-request-object")) {
                        try {
                            httpGet.get(request.value.value.toURL())
                        } catch (t: Throwable) {
                            throw CredentialOfferRequestError.UnableToFetchCredentialOffer(t).toException()
                        }
                    }
            }
            val credentialOfferRequestObject = runCatching {
                Json.decodeFromString<CredentialOfferRequestTO>(credentialOfferRequestObjectString)
            }.getOrElse { CredentialOfferRequestError.NonParseableCredentialOffer(it).raise() }

            val credentialIssuerId = CredentialIssuerId(credentialOfferRequestObject.credentialIssuerIdentifier)
                .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).raise() }

            val credentialIssuerMetadata = credentialIssuerMetadataResolver.resolve(credentialIssuerId)
                .getOrElse { CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata(it).raise() }

            val authorizationServerMetadata =
                authorizationServerMetadataResolver.resolve(credentialIssuerMetadata.authorizationServer)
                    .getOrElse { CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata(it).raise() }

            val credentials = runCatching {
                credentialOfferRequestObject.credentials
                    .map { it.toOfferedCredentialByProfile(credentialIssuerMetadata) }
                    .also {
                        require(it.isNotEmpty()) { "credentials are required" }
                    }
            }.getOrElse { CredentialOfferRequestValidationError.InvalidCredentials(it).raise() }

            val grants = runCatching {
                credentialOfferRequestObject.grants?.toGrants()
            }.getOrElse { CredentialOfferRequestValidationError.InvalidGrants(it).raise() }

            CredentialOffer(
                credentialIssuerId,
                credentialIssuerMetadata,
                authorizationServerMetadata,
                credentials,
                grants,
            )
        }

    companion object {

        /**
         * Tries to parse a [GrantsTO] to a [Grants] instance.
         */
        private fun GrantsTO.toGrants(): Grants? {
            val maybeAuthorizationCodeGrant =
                authorizationCode?.let { Grants.AuthorizationCode(it.issuerState) }
            val maybePreAuthorizedCodeGrant =
                preAuthorizedCode?.let {
                    Grants.PreAuthorizedCode(
                        it.preAuthorizedCode,
                        it.pinRequired ?: false,
                        it.interval?.seconds ?: 5.seconds,
                    )
                }

            return when {
                maybeAuthorizationCodeGrant != null && maybePreAuthorizedCodeGrant != null -> Grants.Both(
                    maybeAuthorizationCodeGrant,
                    maybePreAuthorizedCodeGrant,
                )

                maybeAuthorizationCodeGrant == null && maybePreAuthorizedCodeGrant == null -> null
                maybeAuthorizationCodeGrant != null -> maybeAuthorizationCodeGrant
                else -> maybePreAuthorizedCodeGrant
            }
        }

        /**
         * Tries to parse a [JsonElement] as an [CredentialMetadata].
         */
        private fun JsonElement.toOfferedCredentialByProfile(metadata: CredentialIssuerMetadata): CredentialMetadata =
            if (this is JsonPrimitive && isString) {
                metadata.toOfferedCredentialByScope(content)
            } else if (this is JsonObject) {
                toOfferedCredentialByProfile(metadata)
            } else {
                throw IllegalArgumentException("Invalid JsonElement for Credential. Found '$javaClass'")
            }

        /**
         * Gets an [CredentialMetadata] by its scope.
         */
        private fun CredentialIssuerMetadata.toOfferedCredentialByScope(scope: String): CredentialMetadata =
            credentialsSupported
                .firstOrNull { it.scope == scope }
                ?.let {
                    CredentialMetadata.ByScope(Scope.of(scope))
                }
                ?: throw IllegalArgumentException("Unknown scope '$scope")

        /**
         * Converts this [JsonObject] to a [CredentialMetadata.ByFormat] object.
         *
         * The resulting [CredentialMetadata.ByFormat] must be supported by the Credential Issuer and be present in its [CredentialIssuerMetadata].
         */
        private fun JsonObject.toOfferedCredentialByProfile(metadata: CredentialIssuerMetadata): CredentialMetadata {
            val format =
                getOrDefault("format", JsonNull)
                    .let {
                        if (it is JsonPrimitive && it.isString) {
                            it.content
                        } else {
                            throw IllegalArgumentException("Invalid 'format'")
                        }
                    }

            return FormatRegistry.byFormat(format).matchSupportedAndToDomain(this, metadata)
        }
    }
}
