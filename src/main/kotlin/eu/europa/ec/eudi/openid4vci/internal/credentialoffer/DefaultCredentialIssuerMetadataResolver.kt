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
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*

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
            Json.decodeFromString<CredentialIssuerMetadataTO>(credentialIssuerMetadataContent)
        }.getOrElse { CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(it).raise() }

        credentialIssuerMetadataObject.toDomain()
            .also {
                if (it.credentialIssuerIdentifier != issuer) {
                    InvalidCredentialIssuerId(
                        IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                    ).raise()
                }
            }
    }

    companion object {

        /**
         * Converts and validates  a [CredentialIssuerMetadataTO] as a [CredentialIssuerMetadata] instance.
         */
        private fun CredentialIssuerMetadataTO.toDomain(): CredentialIssuerMetadata {
            val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
                .getOrElse { InvalidCredentialIssuerId(it).raise() }

            val authorizationServer =
                authorizationServer
                    ?.let {
                        HttpsUrl(it).getOrElse { error ->
                            InvalidAuthorizationServer(error).raise()
                        }
                    }
                    ?: credentialIssuerIdentifier.value

            val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
                .getOrElse { InvalidCredentialEndpoint(it).raise() }

            val batchCredentialEndpoint =
                batchCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            InvalidBatchCredentialEndpoint(error).raise()
                        }
                    }

            val deferredCredentialEndpoint =
                deferredCredentialEndpoint
                    ?.let {
                        CredentialIssuerEndpoint(it).getOrElse { error ->
                            InvalidDeferredCredentialEndpoint(error).raise()
                        }
                    }

            fun credentialResponseEncryption(): Result<CredentialResponseEncryption> = runCatching {
                val requireEncryption = requireCredentialResponseEncryption ?: false
                val encryptionAlgorithms = try {
                    credentialResponseEncryptionAlgorithmsSupported?.map { JWEAlgorithm.parse(it) } ?: emptyList()
                } catch (it: Throwable) {
                    InvalidCredentialResponseEncryptionAlgorithmsSupported(it).raise()
                }
                val encryptionMethods = try {
                    credentialResponseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) } ?: emptyList()
                } catch (it: Throwable) {
                    InvalidCredentialResponseEncryptionMethodsSupported(it).raise()
                }

                if (requireEncryption) {
                    if (encryptionAlgorithms.isEmpty()) {
                        CredentialResponseEncryptionAlgorithmsRequired.raise()
                    }

                    CredentialResponseEncryption.Required(
                        encryptionAlgorithms,
                        encryptionMethods,
                    )
                } else {
                    require(encryptionAlgorithms.isEmpty())
                    require(encryptionMethods.isEmpty())
                    CredentialResponseEncryption.NotRequired
                }
            }

            val credentialsSupported = runCatching {
                credentialsSupported
                    .map { it.toCredentialSupportedObject() }
                    .map { it.toDomain() }
            }.getOrElse { InvalidCredentialsSupported(it).raise() }
                .ifEmpty {
                    CredentialsSupportedRequired.raise()
                }

            val display = runCatching {
                display?.map { it.toDomain() } ?: emptyList()
            }.getOrElse { InvalidDisplay(it).raise() }

            return CredentialIssuerMetadata(
                credentialIssuerIdentifier,
                authorizationServer,
                credentialEndpoint,
                batchCredentialEndpoint,
                deferredCredentialEndpoint,
                credentialResponseEncryption().getOrThrow(),
                credentialsSupported,
                display,
            )
        }

        /**
         * Converts a [JsonObject] to a [CredentialSupportedTO].
         */
        private fun JsonObject.toCredentialSupportedObject(): CredentialSupportedTO {
            val format =
                getOrDefault("format", JsonNull).let {
                    if (it is JsonPrimitive && it.isString) {
                        it.content
                    } else {
                        throw IllegalArgumentException("'format' must be a JsonPrimitive that contains a string")
                    }
                }

            return when (format) {
                W3CSignedJwtProfile.FORMAT -> Json.decodeFromJsonElement<W3CSignedJwtProfile.CredentialSupportedTO>(
                    this,
                )

                W3CJsonLdSignedJwtProfile.FORMAT -> Json.decodeFromJsonElement<W3CJsonLdSignedJwtProfile.CredentialSupportedTO>(
                    this,
                )

                W3CJsonLdDataIntegrityProfile.FORMAT -> Json.decodeFromJsonElement<W3CJsonLdDataIntegrityProfile.CredentialSupportedTO>(
                    this,
                )

                MsoMdocProfile.FORMAT -> Json.decodeFromJsonElement<MsoMdocProfile.CredentialSupportedTO>(
                    this,
                )

                SdJwtVcProfile.FORMAT -> Json.decodeFromJsonElement<SdJwtVcProfile.CredentialSupportedObject>(
                    this,
                )

                else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
            }
        }

        /**
         * Converts a [CredentialIssuerMetadataTO.DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
         */
        private fun CredentialIssuerMetadataTO.DisplayTO.toDomain(): CredentialIssuerMetadata.Display =
            CredentialIssuerMetadata.Display(name, locale)
    }
}
