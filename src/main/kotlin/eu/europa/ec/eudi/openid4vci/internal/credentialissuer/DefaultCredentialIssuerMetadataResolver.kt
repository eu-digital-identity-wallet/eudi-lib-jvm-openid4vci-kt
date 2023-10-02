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
package eu.europa.ec.eudi.openid4vci.internal.credentialissuer

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialSupportedObject.*
import io.ktor.http.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import java.net.URL

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
internal class DefaultCredentialIssuerMetadataResolver(
    private val ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
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
            fetch(url)
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

    /**
     * Tries to fetch the content of the provided [url] as a [String] using the configured [httpGet] using [ioCoroutineDispatcher].
     */
    private suspend fun fetch(url: URL): String =
        withContext(ioCoroutineDispatcher + CoroutineName("/.well-known/openid-credential-issuer")) {
            httpGet.get(url).getOrThrow()
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
                credentialResponseEncryptionAlgorithmsSupported.map { JWEAlgorithm.parse(it) }
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionAlgorithmsSupported(
                    it,
                ).raise()
            }

            val credentialResponseEncryptionMethodsSupported = runCatching {
                credentialResponseEncryptionMethodsSupported.map { EncryptionMethod.parse(it) }
            }.getOrElse {
                CredentialIssuerMetadataValidationError.InvalidCredentialResponseEncryptionMethodsSupported(it).raise()
            }

            val requireCredentialResponseEncryption = requireCredentialResponseEncryption ?: false
            if (requireCredentialResponseEncryption && credentialResponseEncryptionAlgorithmsSupported.isEmpty()) {
                CredentialIssuerMetadataValidationError.CredentialResponseEncryptionAlgorithmsRequired.raise()
            }

            val credentialsSupported = runCatching {
                credentialsSupported.map { it.toSupportedCredentialObject() }
            }.getOrElse { CredentialIssuerMetadataValidationError.InvalidCredentialsSupported(it).raise() }
            if (credentialsSupported.isEmpty()) {
                CredentialIssuerMetadataValidationError.CredentialsSupportedRequired.raise()
            }

            val display = runCatching {
                display.map { it.toDomain() }
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
        private fun JsonObject.toSupportedCredentialObject(): CredentialSupportedObject {
            val format =
                getOrDefault("format", JsonNull).let {
                    if (it is JsonPrimitive && it.isString) {
                        it.content
                    } else {
                        throw IllegalArgumentException("'format' must be a JsonPrimitive that contains a string")
                    }
                }

            return when (format) {
                "jwt_vc_json" -> Json.decodeFromJsonElement<W3CVerifiableCredentialSignedJwtCredentialSupportedObject>(
                    this,
                )

                "jwt_vc_json-ld" -> Json.decodeFromJsonElement<W3CVerifiableCredentialJsonLdSignedJwtCredentialSupportedObject>(
                    this,
                )

                "ldp_vc" -> Json.decodeFromJsonElement<W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupportedObject>(
                    this,
                )

                "mso_mdoc" -> Json.decodeFromJsonElement<MsoMdocCredentialSupportedObject>(this)

                else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
            }
        }

        /**
         * Converts a [CredentialIssuerMetadataObject.DisplayObject] to a [CredentialIssuerMetadata.Display] instance.
         */
        private fun CredentialIssuerMetadataObject.DisplayObject.toDomain(): CredentialIssuerMetadata.Display =
            CredentialIssuerMetadata.Display(name, locale)
    }
}
