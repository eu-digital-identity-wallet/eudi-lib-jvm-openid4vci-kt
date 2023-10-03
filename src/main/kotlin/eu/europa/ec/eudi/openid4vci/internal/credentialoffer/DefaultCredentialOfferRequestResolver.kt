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
import eu.europa.ec.eudi.openid4vci.CredentialSupportedObject.*
import eu.europa.ec.eudi.openid4vci.OfferedCredential.W3CVerifiableCredential
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.UnresolvedCredential.UnresolvedScopedCredential
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.UnresolvedCredential.UnresolvedUnscopedCredential
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.UnresolvedCredential.UnresolvedUnscopedCredential.UnresolvedMsoMdocCredential
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.UnresolvedCredential.UnresolvedUnscopedCredential.UnresolvedW3CVerifiableCredential
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.time.Duration

/**
 * A default implementation for [CredentialOfferRequestResolver].
 */
internal class DefaultCredentialOfferRequestResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher,
    private val httpGet: HttpGet<String>,
) : CredentialOfferRequestResolver {

    private val credentialIssuerMetadataResolver = CredentialIssuerMetadataResolver(ioCoroutineDispatcher, httpGet)

    override suspend fun resolve(request: CredentialOfferRequest): Result<CredentialOffer> =
        runCatching {
            val credentialOfferRequestObjectString: String = when (request) {
                is CredentialOfferRequest.PassByValue -> request.value
                is CredentialOfferRequest.PassByReference ->
                    withContext(ioCoroutineDispatcher + CoroutineName("credential-offer-request-object")) {
                        httpGet.get(request.value.value.toURL()).getOrElse {
                            CredentialOfferRequestError.UnableToFetchCredentialOffer(it).raise()
                        }
                    }
            }
            val credentialOfferRequestObject = runCatching {
                Json.decodeFromString<CredentialOfferRequestObject>(credentialOfferRequestObjectString)
            }.getOrElse { CredentialOfferRequestError.NonParseableCredentialOffer(it).raise() }

            val credentialIssuerId = CredentialIssuerId(credentialOfferRequestObject.credentialIssuerIdentifier)
                .getOrElse { CredentialOfferRequestValidationError.InvalidCredentialIssuerId(it).raise() }

            val credentialIssuerMetadata = credentialIssuerMetadataResolver.resolve(credentialIssuerId)
                .getOrElse { CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata(it).raise() }

            val credentials = runCatching {
                credentialOfferRequestObject.credentials
                    .map { it.toUnresolvedCredential() }
                    .map {
                        when (it) {
                            is UnresolvedScopedCredential -> it.toOfferedCredential(credentialIssuerMetadata)
                            is UnresolvedUnscopedCredential -> it.toOfferedCredential()
                        }
                    }
                    .also {
                        require(it.isNotEmpty()) { "credentials are required" }
                    }
            }.getOrElse { CredentialOfferRequestValidationError.InvalidCredentials(it).raise() }

            val grants = runCatching {
                credentialOfferRequestObject.grants?.toGrants()
            }.getOrElse { CredentialOfferRequestValidationError.InvalidGrants(it).raise() }

            CredentialOffer(credentialIssuerId, credentialIssuerMetadata, credentials, grants)
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
         * Tries to parse a [JsonElement] to a [UnresolvedCredential] instance.
         */
        private fun JsonElement.toUnresolvedCredential(): UnresolvedCredential =
            if (this is JsonPrimitive && isString) {
                UnresolvedScopedCredential(content)
            } else if (this is JsonObject) {
                toUnresolvedUnscopedCredential()
            } else {
                throw IllegalArgumentException("Invalid JsonElement for Credential. Found '$javaClass'")
            }

        /**
         * Tries to parse a [JsonObject] to an [UnresolvedCredential.UnresolvedUnscopedCredential].
         */
        private fun JsonObject.toUnresolvedUnscopedCredential(): UnresolvedUnscopedCredential {
            fun toMsoMdocCredential() =
                UnresolvedMsoMdocCredential(
                    Json.decodeFromJsonElement<MsoMdocCredentialObject>(
                        this,
                    ).docType,
                )

            fun toW3CVerifiableCredential(constructor: (CredentialDefinition) -> UnresolvedW3CVerifiableCredential) =
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
                "jwt_vc_json" -> toW3CVerifiableCredential(UnresolvedW3CVerifiableCredential::SignedJwt)
                "jwt_vc_json-ld" -> toW3CVerifiableCredential(UnresolvedW3CVerifiableCredential::JsonLdSignedJwt)
                "ldp_vc" -> toW3CVerifiableCredential(UnresolvedW3CVerifiableCredential::JsonLdDataIntegrity)
                else -> throw IllegalArgumentException("Unknown Credential format '$format'")
            }
        }
    }
}

/**
 * Credentials offered in a Credential Offer Request.
 */
private sealed interface UnresolvedCredential {

    /**
     * A Credential identified by its Scope.
     */
    data class UnresolvedScopedCredential(
        val scope: String,
    ) : UnresolvedCredential {

        /**
         * Resolves and converts this [UnresolvedScopedCredential] to an [OfferedCredential].
         */
        fun toOfferedCredential(metadata: CredentialIssuerMetadata): OfferedCredential =
            metadata.credentialsSupported
                .firstOrNull { it.scope == scope }
                ?.let {
                    when (it) {
                        is MsoMdocCredentialSupportedObject -> OfferedCredential.MsoMdocCredential(it.docType, it.scope)
                        is W3CVerifiableCredentialSignedJwtCredentialSupportedObject ->
                            W3CVerifiableCredential.SignedJwt(
                                it.credentialDefinition,
                                it.scope,
                            )

                        is W3CVerifiableCredentialJsonLdSignedJwtCredentialSupportedObject ->
                            W3CVerifiableCredential.JsonLdSignedJwt(
                                it.credentialDefinition,
                                it.scope,
                            )

                        is W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupportedObject ->
                            W3CVerifiableCredential.JsonLdDataIntegrity(
                                it.credentialDefinition,
                                it.scope,
                            )
                    }
                }
                ?: throw IllegalArgumentException("Unknown scope '$scope")
    }

    /**
     * A Credential format not identified by a Scope.
     */
    sealed interface UnresolvedUnscopedCredential : UnresolvedCredential {

        /**
         * Converts this [UnresolvedUnscopedCredential] to an [UnresolvedCredential].
         */
        fun toOfferedCredential(): OfferedCredential

        /**
         * An MSO MDOC credential.
         */
        data class UnresolvedMsoMdocCredential(
            val docType: String,
        ) : UnresolvedUnscopedCredential {
            override fun toOfferedCredential() = OfferedCredential.MsoMdocCredential(docType)
        }

        /**
         * A W3C Verifiable Credential.
         */
        sealed interface UnresolvedW3CVerifiableCredential : UnresolvedUnscopedCredential {

            /**
             * A signed JWT not using JSON-LD.
             *
             * Format: jwt_vc_json
             */
            data class SignedJwt(
                val credentialDefinition: CredentialDefinition,
            ) : UnresolvedW3CVerifiableCredential {
                override fun toOfferedCredential() = W3CVerifiableCredential.SignedJwt(credentialDefinition)
            }

            /**
             * A signed JWT using JSON-LD.
             *
             * Format: jwt_vc_json-ld
             */
            data class JsonLdSignedJwt(
                val credentialDefinition: CredentialDefinition,
            ) : UnresolvedW3CVerifiableCredential {
                override fun toOfferedCredential() = W3CVerifiableCredential.JsonLdSignedJwt(credentialDefinition)
            }

            /**
             * Data Integrity using JSON-LD.
             *
             * Format: ldp_vc
             */
            data class JsonLdDataIntegrity(
                val credentialDefinition: CredentialDefinition,
            ) : UnresolvedW3CVerifiableCredential {
                override fun toOfferedCredential() = W3CVerifiableCredential.JsonLdDataIntegrity(credentialDefinition)
            }
        }
    }
}
