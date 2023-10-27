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
        }.getOrThrow { CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(it) }

        val credentialIssuerMetadataObject = try {
            Json.decodeFromString<CredentialIssuerMetadataTO>(credentialIssuerMetadataContent)
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(t)
        }

        credentialIssuerMetadataObject.toDomain().apply {
            if (credentialIssuerIdentifier != issuer) {
                throw InvalidCredentialIssuerId(
                    IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                )
            }
        }
    }
}

/**
 * Converts and validates  a [CredentialIssuerMetadataTO] as a [CredentialIssuerMetadata] instance.
 */
private fun CredentialIssuerMetadataTO.toDomain(): CredentialIssuerMetadata {
    val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
        .getOrThrow { InvalidCredentialIssuerId(it) }

    val authorizationServer =
        authorizationServer
            ?.let {
                HttpsUrl(it).getOrElse { error ->
                    throw InvalidAuthorizationServer(error)
                }
            }
            ?: credentialIssuerIdentifier.value

    val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
        .getOrThrow(::InvalidCredentialEndpoint)

    val batchCredentialEndpoint =
        batchCredentialEndpoint
            ?.let {
                CredentialIssuerEndpoint(it).getOrThrow(::InvalidBatchCredentialEndpoint)
            }

    val deferredCredentialEndpoint =
        deferredCredentialEndpoint
            ?.let {
                CredentialIssuerEndpoint(it).getOrThrow(::InvalidDeferredCredentialEndpoint)
            }

    fun credentialResponseEncryption(): Result<CredentialResponseEncryption> = runCatching {
        val requireEncryption = requireCredentialResponseEncryption ?: false
        val encryptionAlgorithms =
            credentialResponseEncryptionAlgorithmsSupported?.map {
                JWEAlgorithm.parse(it)
            } ?: emptyList()

        val encryptionMethods =
            credentialResponseEncryptionMethodsSupported?.map { EncryptionMethod.parse(it) } ?: emptyList()

        if (requireEncryption) {
            if (encryptionAlgorithms.isEmpty()) {
                throw CredentialResponseEncryptionAlgorithmsRequired
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

    val credentialsSupported = try {
        credentialsSupported.map { it.toCredentialSupportedObject().getOrThrow().toDomain() }
    } catch (it: Throwable) {
        throw InvalidCredentialsSupported(it)
    }.apply {
        ifEmpty { throw CredentialsSupportedRequired }
    }

    val display = display?.map { it.toDomain() } ?: emptyList()

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
private fun JsonObject.toCredentialSupportedObject(): Result<CredentialSupportedTO> = runCatching {
    val format =
        getOrDefault("format", JsonNull).let { jsonElement ->

            require(jsonElement is JsonPrimitive && jsonElement.isString) {
                "'format' must be a JsonPrimitive that contains a string"
            }
            jsonElement.content
        }

    when (format) {
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

private fun <T> Result<T>.getOrThrow(f: (Throwable) -> Throwable): T =
    fold(onSuccess = { it }, onFailure = { throw f(it) })
