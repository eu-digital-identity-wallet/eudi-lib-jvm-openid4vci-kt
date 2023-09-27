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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.Credential.UnscopedCredential
import eu.europa.ec.eudi.openid4vci.Credential.UnscopedCredential.W3CVerifiableCredential
import kotlinx.serialization.json.*
import java.time.Duration

/**
 * A default implementation for [CredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolver : CredentialOfferRequestResolver {

    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatching {
            val credentialOfferRequestObject = when (request) {
                is CredentialOfferRequest.PassByValue -> deserialize(request.value)
                is CredentialOfferRequest.PassByReference -> TODO()
            }.getOrThrow()

            val credentialIssuerId = CredentialIssuerId(credentialOfferRequestObject.credentialIssuerIdentifier)
                .getOrElse { throw CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).toException() }

            val credentials = runCatching {
                credentialOfferRequestObject.credentials.map { it.toCredential().getOrThrow() }
            }.getOrElse { throw CredentialOfferRequestValidationError.InvalidCredentials(it).toException() }

            val grants = credentialOfferRequestObject.grants
                ?.grants()
                ?.getOrElse { throw CredentialOfferRequestValidationError.InvalidGrants(it).toException() }

            CredentialOffer(credentialIssuerId, credentials, grants)
        }

    companion object {

        /**
         * Tries to decode a [JsonString] to a [CredentialOfferRequestObject].
         */
        private fun deserialize(value: JsonString): Result<CredentialOfferRequestObject> =
            runCatching {
                Json.decodeFromString<CredentialOfferRequestObject>(value)
            }.recoverCatching {
                throw CredentialOfferRequestValidationError.NonParseableCredentialOffer(it).toException()
            }

        /**
         * Tries to parse a [GrantsObject] to a [Grants] instance.
         */
        private fun GrantsObject.grants(): Result<Grants?> = runCatching {
            val maybeAuthorizationCodeGrant =
                authorizationCode?.let { Grants.AuthorizationCode(it.issuerState) }
            val maybePreAuthorizedCodeGrant =
                preAuthorizedCode?.let {
                    Grants.PreAuthorizedCode(
                        it.preAuthorizedCode,
                        it.pinRequired ?: false,
                        it.interval?.let { interval -> Duration.ofSeconds(interval) } ?: Duration.ofSeconds(5L),
                    )
                }

            when {
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
         * Tries to parse a [JsonElement] to a [Credential] instance.
         */
        private fun JsonElement.toCredential(): Result<Credential> = runCatching {
            if (this is JsonPrimitive && isString) {
                Credential.ScopedCredential(content)
            } else if (this is JsonObject) {
                toUnscopedCredential().getOrThrow()
            } else {
                throw CredentialOfferRequestValidationError.InvalidCredential(
                    IllegalArgumentException("Invalid JsonElement for Credential. Found '$javaClass'"),
                ).toException()
            }
        }

        /**
         * Tries to deserialize a [JsonElement] as a [T].
         * In case of failure an exception mapped by [errorMapper] is thrown.
         */
        private inline fun <reified T, E : Exception> JsonElement.deserialize(errorMapper: (Throwable) -> E): T =
            runCatching {
                Json.decodeFromJsonElement<T>(this)
            }.recoverCatching {
                throw errorMapper(it)
            }.getOrThrow()

        /**
         * Tries to parse a [JsonObject] to an [Credential.UnscopedCredential].
         */
        private fun JsonObject.toUnscopedCredential(): Result<UnscopedCredential> = runCatching {
            fun format(): String =
                getOrDefault("format", JsonNull)
                    .let {
                        if (it is JsonPrimitive && it.isString) {
                            it.content
                        } else {
                            throw CredentialOfferRequestValidationError.InvalidCredential(
                                IllegalArgumentException("Invalid 'format'"),
                            ).toException()
                        }
                    }

            when (val format = format()) {
                "mso_mdoc" -> UnscopedCredential.MsoMdocCredential(
                    deserialize { CredentialOfferRequestValidationError.InvalidCredential(it).toException() },
                )

                "jwt_vc_json" -> W3CVerifiableCredential.SignedJwt(
                    deserialize { CredentialOfferRequestValidationError.InvalidCredential(it).toException() },
                )

                "jwt_vc_json-ld" -> W3CVerifiableCredential.JsonLdSignedJwt(
                    deserialize { CredentialOfferRequestValidationError.InvalidCredential(it).toException() },
                )

                "ldp_vc" -> W3CVerifiableCredential.JsonLdDataIntegrity(
                    deserialize { CredentialOfferRequestValidationError.InvalidCredential(it).toException() },
                )

                else -> UnscopedCredential.UnknownCredential(format, this)
            }
        }
    }
}
