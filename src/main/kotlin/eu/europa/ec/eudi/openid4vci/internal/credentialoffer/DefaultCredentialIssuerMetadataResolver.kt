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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.net.URL
import java.util.*

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
internal class DefaultCredentialIssuerMetadataResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher,
    private val httpGet: HttpGet<String>,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> = runCatching {
        val credentialIssuerMetadataContent = runCatching {
            val url =
                URLBuilder(issuer.value.value.toString())
                    .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
                    .build()
                    .toURI()
                    .toURL()

            withContext(ioCoroutineDispatcher + CoroutineName("/.well-known/openid-credential-issuer")) {
                httpGet.get(url).getOrThrow()
            }
        }.getOrElse { CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(it).raise() }

        val credentialIssuerMetadataObject = runCatching {
            Json.decodeFromString<CredentialIssuerMetadataObject>(credentialIssuerMetadataContent)
        }.getOrElse { CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(it).raise() }

        credentialIssuerMetadataObject.toDomain()
            .also {
                if (it.credentialIssuerIdentifier != issuer) {
                    CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId(
                        IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                    ).raise()
                }
            }
    }

    companion object {

        /**
         * Converts and validates  a [CredentialIssuerMetadataObject] as a [CredentialIssuerMetadata] instance.
         */
        private fun CredentialIssuerMetadataObject.toDomain(): CredentialIssuerMetadata {
            val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
                .getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId(it).raise() }

            val authorizationServer =
                authorizationServer
                    ?.let {
                        HttpsUrl(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidAuthorizationServer(error).raise()
                        }
                    }
                    ?: credentialIssuerIdentifier.value

            val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
                .getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialEndpoint(it).raise() }

            val batchCredentialEndpoint =
                batchCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidBatchCredentialEndpoint(error).raise()
                        }
                    }

            val deferredCredentialEndpoint =
                deferredCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            CredentialIssuerMetadataValidationError.InvalidDeferredCredentialEndpoint(error).raise()
                        }
                    }

            val credentialResponseEncryptionAlgorithmsSupported = runCatching {
                credentialResponseEncryptionAlgorithmsSupported?.map { JWEAlgorithm.parse(it) } ?: emptyList()
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionAlgorithmsSupported(
                    it,
                ).raise()
            }

            val credentialResponseEncryptionMethodsSupported = runCatching {
                credentialResponseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) } ?: emptyList()
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionMethodsSupported(it).raise()
            }

            val requireCredentialResponseEncryption = requireCredentialResponseEncryption ?: false
            if (requireCredentialResponseEncryption && credentialResponseEncryptionAlgorithmsSupported.isEmpty()) {
                CredentialIssuerMetadataValidationError.CredentialResponseEncryptionAlgorithmsRequired.raise()
            }

            val credentialsSupported = runCatching {
                credentialsSupported
                    .map { it.toCredentialSupportedObject() }
                    .map { it.toCredentialSupported() }
            }.getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialsSupported(it).raise() }
                .ifEmpty {
                    CredentialIssuerMetadataValidationError.CredentialsSupportedRequired.raise()
                }

            val display = runCatching {
                display?.map { it.toDomain() } ?: emptyList()
            }.getOrElse { CredentialIssuerMetadataValidationError.InvalidDisplay(it).raise() }

            return CredentialIssuerMetadata(
                credentialIssuerIdentifier,
                authorizationServer,
                credentialEndpoint,
                batchCredentialEndpoint,
                deferredCredentialEndpoint,
                credentialResponseEncryptionAlgorithmsSupported,
                credentialResponseEncryptionMethodsSupported,
                requireCredentialResponseEncryption,
                credentialsSupported,
                display,
            )
        }

        /**
         * Converts a [JsonObject] to a [CredentialSupportedObject].
         */
        private fun JsonObject.toCredentialSupportedObject(): CredentialSupportedObject {
            val format =
                getOrDefault("format", JsonNull).let {
                    if (it is JsonPrimitive && it.isString) {
                        it.content
                    } else {
                        throw IllegalArgumentException("'format' must be a JsonPrimitive that contains a string")
                    }
                }

            return when (format) {
                "jwt_vc_json" -> Json.decodeFromJsonElement<CredentialSupportedObject.SignedJwt>(
                    this,
                )

                "jwt_vc_json-ld" -> Json.decodeFromJsonElement<CredentialSupportedObject.JsonLdSignedJwt>(
                    this,
                )

                "ldp_vc" -> Json.decodeFromJsonElement<CredentialSupportedObject.JsonLdDataIntegrity>(
                    this,
                )

                "mso_mdoc" -> Json.decodeFromJsonElement<CredentialSupportedObject.MsoMdoc>(
                    this,
                )

                else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
            }
        }

        /**
         * Converts a [CredentialSupportedObject] to a [CredentialSupported].
         */
        private fun CredentialSupportedObject.toCredentialSupported(): CredentialSupported {
            val cryptographicBindingMethodsSupported =
                cryptographicBindingMethodsSupported?.map {
                    when (it) {
                        "jwk" -> CryptographicBindingMethod.JWK
                        "cose_key" -> CryptographicBindingMethod.COSE
                        "mso" -> CryptographicBindingMethod.MSO
                        else ->
                            if (it.startsWith("did")) {
                                CryptographicBindingMethod.DID(it)
                            } else {
                                throw IllegalArgumentException("Unknown Cryptographic Binding Method '$it'")
                            }
                    }
                } ?: emptyList()
            val cryptographicSuitesSupported = cryptographicSuitesSupported ?: emptyList()
            val proofTypesSupported =
                proofTypesSupported
                    ?.map {
                        when (it) {
                            "jwt" -> ProofType.JWT
                            "cwt" -> ProofType.CWT
                            else -> throw IllegalArgumentException("Unknown Proof Type '$it'")
                        }
                    } ?: emptyList<ProofType>()
                    .ifEmpty {
                        listOf(ProofType.JWT)
                    }

            fun DisplayObject.toDisplay(): Display {
                fun DisplayObject.LogoObject.toLogo(): Display.Logo =
                    Display.Logo(
                        url?.let { HttpsUrl(it).getOrThrow() },
                        alternativeText,
                    )

                return Display(
                    name,
                    locale?.let { Locale.forLanguageTag(it) },
                    logo?.toLogo(),
                    description,
                    backgroundColor,
                    textColor,
                )
            }

            val display = display?.map { it.toDisplay() } ?: emptyList()

            fun CredentialSupportedObject.MsoMdoc.claims(): MsoMdocClaims =
                claims?.mapValues { namespaceAndClaims ->
                    namespaceAndClaims.value.mapValues { claimNameAndClaim ->
                        claimNameAndClaim.value.let { claimObject ->
                            Claim(
                                claimObject.mandatory ?: false,
                                claimObject.valueType,
                                claimObject.display?.map { displayObject ->
                                    Claim.Display(
                                        displayObject.name,
                                        displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                                    )
                                } ?: emptyList(),
                            )
                        }
                    }
                } ?: emptyMap()

            fun CredentialDefinitionObject.transform(): CredentialDefinition.NonLd =
                CredentialDefinition.NonLd(
                    type = types,
                    credentialSubject = credentialSubject?.mapValues { nameAndClaim ->
                        nameAndClaim.value.let {
                            Claim(
                                it.mandatory ?: false,
                                it.valueType,
                                it.display?.map { displayObject ->
                                    Claim.Display(
                                        displayObject.name,
                                        displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                                    )
                                } ?: emptyList(),
                            )
                        }
                    },
                )

            fun CredentialDefinitionObjectLD.transform(): CredentialDefinition.LdSpecific =
                CredentialDefinition.LdSpecific(
                    context = context.map { URL(it) },
                    type = types,
                    credentialSubject = credentialSubject?.mapValues { nameAndClaim ->
                        nameAndClaim.value.let {
                            Claim(
                                it.mandatory ?: false,
                                it.valueType,
                                it.display?.map { displayObject ->
                                    Claim.Display(
                                        displayObject.name,
                                        displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                                    )
                                } ?: emptyList(),
                            )
                        }
                    },
                )

            return when (this) {
                is CredentialSupportedObject.SignedJwt ->
                    CredentialSupported.SignedJwt(
                        scope,
                        cryptographicBindingMethodsSupported,
                        cryptographicSuitesSupported,
                        proofTypesSupported,
                        display,
                        credentialDefinition.transform(),
                        order ?: emptyList(),
                    )

                is CredentialSupportedObject.JsonLdSignedJwt ->
                    CredentialSupported.JsonLdSignedJwt(
                        scope,
                        cryptographicBindingMethodsSupported,
                        cryptographicSuitesSupported,
                        proofTypesSupported,
                        display,
                        context,
                        credentialDefinition.transform(),
                        order ?: emptyList(),
                    )

                is CredentialSupportedObject.JsonLdDataIntegrity ->
                    CredentialSupported.JsonLdDataIntegrity(
                        scope,
                        cryptographicBindingMethodsSupported,
                        cryptographicSuitesSupported,
                        proofTypesSupported,
                        display,
                        context,
                        type,
                        credentialDefinition.transform(),
                        order ?: emptyList(),
                    )

                is CredentialSupportedObject.MsoMdoc ->
                    CredentialSupported.MsoMdoc(
                        scope,
                        cryptographicBindingMethodsSupported,
                        cryptographicSuitesSupported,
                        proofTypesSupported,
                        display,
                        docType,
                        claims(),
                        order ?: emptyList(),
                    )
            }
        }

        /**
         * Converts a [CredentialIssuerMetadataObject.DisplayObject] to a [CredentialIssuerMetadata.Display] instance.
         */
        private fun CredentialIssuerMetadataObject.DisplayObject.toDomain(): CredentialIssuerMetadata.Display =
            CredentialIssuerMetadata.Display(name, locale)
    }
}
