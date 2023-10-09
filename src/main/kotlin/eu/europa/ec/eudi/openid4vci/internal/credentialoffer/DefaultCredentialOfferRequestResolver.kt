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
import eu.europa.ec.eudi.openid4vci.CredentialSupported.MsoMdocCredentialCredentialSupported
import eu.europa.ec.eudi.openid4vci.CredentialSupported.W3CVerifiableCredentialCredentialSupported
import eu.europa.ec.eudi.openid4vci.CredentialSupported.W3CVerifiableCredentialCredentialSupported.*
import eu.europa.ec.eudi.openid4vci.OfferedCredential.MsoMdocCredential
import eu.europa.ec.eudi.openid4vci.OfferedCredential.W3CVerifiableCredential
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
                    .map { it.toOfferedCredential(credentialIssuerMetadata) }
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
         * Tries to parse a [JsonElement] as an [OfferedCredential].
         */
        private fun JsonElement.toOfferedCredential(metadata: CredentialIssuerMetadata): OfferedCredential =
            if (this is JsonPrimitive && isString) {
                metadata.getOfferedCredentialByScope(content)
            } else if (this is JsonObject) {
                toOfferedCredential(metadata)
            } else {
                throw IllegalArgumentException("Invalid JsonElement for Credential. Found '$javaClass'")
            }

        /**
         * Gets an [OfferedCredential] by its scope.
         */
        private fun CredentialIssuerMetadata.getOfferedCredentialByScope(scope: String): OfferedCredential =
            credentialsSupported
                .firstOrNull { it.scope == scope }
                ?.let {
                    when (it) {
                        is MsoMdocCredentialCredentialSupported -> MsoMdocCredential(it.docType, it.scope)
                        is W3CVerifiableCredentialSignedJwtCredentialSupported ->
                            W3CVerifiableCredential.SignedJwt(
                                it.credentialDefinition,
                                it.scope,
                            )

                        is W3CVerifiableCredentialJsonLdSignedJwtCredentialSupported ->
                            W3CVerifiableCredential.JsonLdSignedJwt(
                                it.credentialDefinition,
                                it.scope,
                            )

                        is W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported ->
                            W3CVerifiableCredential.JsonLdDataIntegrity(
                                it.credentialDefinition,
                                it.scope,
                            )
                    }
                }
                ?: throw IllegalArgumentException("Unknown scope '$scope")

        /**
         * Converts this [JsonObject] to an [OfferedCredential].
         *
         * The resulting [OfferedCredential] must be supported by the Credential Issuer and be present in its [CredentialIssuerMetadata].
         */
        private fun JsonObject.toOfferedCredential(metadata: CredentialIssuerMetadata): OfferedCredential {
            val format =
                getOrDefault("format", JsonNull)
                    .let {
                        if (it is JsonPrimitive && it.isString) {
                            it.content
                        } else {
                            throw IllegalArgumentException("Invalid 'format'")
                        }
                    }

            fun CredentialIssuerMetadata.getMatchingMsoMdocCredential(): MsoMdocCredential {
                val docType = Json.decodeFromJsonElement<MsoMdocCredentialObject>(
                    this@toOfferedCredential,
                ).docType

                fun fail(): Nothing =
                    throw IllegalArgumentException("Unsupported MsoMdocCredential with format '$format' and docType '$docType'")

                return credentialsSupported
                    .firstOrNull {
                        it is MsoMdocCredentialCredentialSupported &&
                            it.docType == docType
                    }
                    ?.let {
                        MsoMdocCredential(docType, (it as MsoMdocCredentialCredentialSupported).scope)
                    }
                    ?: fail()
            }

            fun CredentialIssuerMetadata.getMatchingW3CVerifiableCredential(
                constructor: (CredentialDefinition, String?) -> W3CVerifiableCredential,
            ): W3CVerifiableCredential {
                val credentialDefinition = Json.decodeFromJsonElement<W3CVerifiableCredentialCredentialObject>(
                    this@toOfferedCredential,
                ).credentialDefinition

                fun fail(): Nothing =
                    throw IllegalArgumentException(
                        "Unsupported W3CVerifiableCredential with format '$format' and credentialDefinition '$credentialDefinition'",
                    )

                return credentialsSupported
                    .firstOrNull {
                        it is W3CVerifiableCredentialCredentialSupported &&
                            it.credentialDefinition == credentialDefinition
                    }
                    ?.let {
                        constructor(
                            credentialDefinition,
                            it.scope,
                        )
                    }
                    ?: fail()
            }

            return when (format) {
                "mso_mdoc" -> metadata.getMatchingMsoMdocCredential()
                "jwt_vc_json" -> metadata.getMatchingW3CVerifiableCredential(W3CVerifiableCredential::SignedJwt)
                "jwt_vc_json-ld" -> metadata.getMatchingW3CVerifiableCredential(W3CVerifiableCredential::JsonLdSignedJwt)
                "ldp_vc" -> metadata.getMatchingW3CVerifiableCredential(W3CVerifiableCredential::JsonLdDataIntegrity)
                else -> throw IllegalArgumentException("Unknown Credential format '$format'")
            }
        }
    }
}
