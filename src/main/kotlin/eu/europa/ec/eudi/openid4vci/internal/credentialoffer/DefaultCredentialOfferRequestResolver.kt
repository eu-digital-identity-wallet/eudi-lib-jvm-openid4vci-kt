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
import eu.europa.ec.eudi.openid4vci.OfferedCredential.UnscopedCredential
import eu.europa.ec.eudi.openid4vci.OfferedCredential.UnscopedCredential.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.OfferedCredential.UnscopedCredential.W3CVerifiableCredential
import kotlinx.serialization.json.*
import java.time.Duration

/**
 * A default implementation for [CredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolver : CredentialOfferRequestResolver {

    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatching {
            val credentialOfferRequestObject = runCatching {
                when (request) {
                    is CredentialOfferRequest.PassByValue -> Json.decodeFromString<CredentialOfferRequestObject>(request.value)
                    is CredentialOfferRequest.PassByReference -> TODO()
                }
            }.getOrElse { throw CredentialOfferRequestValidationError.NonParseableCredentialOffer(it).toException() }

            val credentialIssuerId = CredentialIssuerId(credentialOfferRequestObject.credentialIssuerIdentifier)
                .getOrElse { throw CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).toException() }

            val credentials = runCatching {
                credentialOfferRequestObject.credentials.map { it.toCredential() }
            }.getOrElse { throw CredentialOfferRequestValidationError.InvalidCredentials(it).toException() }

            val grants = runCatching {
                credentialOfferRequestObject.grants?.toGrants()
            }.getOrElse { throw CredentialOfferRequestValidationError.InvalidGrants(it).toException() }

            CredentialOffer(credentialIssuerId, credentials, grants)
        }

    companion object {

        /**
         * Tries to parse a [GrantsObject] to a [Grants] instance.
         */
        private fun GrantsObject.toGrants(): Grants? {
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
         * Tries to parse a [JsonElement] to a [OfferedCredential] instance.
         */
        private fun JsonElement.toCredential(): OfferedCredential =
            if (this is JsonPrimitive && isString) {
                OfferedCredential.ScopedCredential(content)
            } else if (this is JsonObject) {
                toUnscopedCredential()
            } else {
                throw IllegalArgumentException("Invalid JsonElement for Credential. Found '$javaClass'")
            }

        /**
         * Tries to parse a [JsonObject] to an [OfferedCredential.UnscopedCredential].
         */
        private fun JsonObject.toUnscopedCredential(): UnscopedCredential {
            fun toMsoMdocCredential(): MsoMdocCredential =
                MsoMdocCredential(Json.decodeFromJsonElement<MsoMdocCredentialObject>(this).docType)

            fun toW3CVerifiableCredential(constructor: (CredentialDefinition) -> W3CVerifiableCredential): W3CVerifiableCredential =
                constructor(Json.decodeFromJsonElement<W3CVerifiableCredentialCredentialObject>(this).credentialDefinition)

            val format =
                getOrDefault("format", JsonNull)
                    .let {
                        if (it is JsonPrimitive && it.isString) {
                            it.content
                        } else {
                            throw IllegalArgumentException("Invalid 'format'")
                        }
                    }

            return when (format) {
                "mso_mdoc" -> toMsoMdocCredential()
                "jwt_vc_json" -> toW3CVerifiableCredential(W3CVerifiableCredential::SignedJwt)
                "jwt_vc_json-ld" -> toW3CVerifiableCredential(W3CVerifiableCredential::JsonLdSignedJwt)
                "ldp_vc" -> toW3CVerifiableCredential(W3CVerifiableCredential::JsonLdDataIntegrity)
                else -> throw IllegalArgumentException("Unknown Credential format '$format'")
            }
        }
    }
}
