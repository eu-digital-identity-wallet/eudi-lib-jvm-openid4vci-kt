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
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupportedTO
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Unvalidated metadata of a Credential Issuer.
 */
@Serializable
private data class CredentialIssuerMetadataTO(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("authorization_server") val authorizationServer: String? = null,
    @SerialName("credential_endpoint") @Required val credentialEndpoint: String,
    @SerialName("batch_credential_endpoint") val batchCredentialEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("credential_response_encryption_alg_values_supported")
    val credentialResponseEncryptionAlgorithmsSupported: List<String>? = null,
    @SerialName("credential_response_encryption_enc_values_supported")
    val credentialResponseEncryptionMethodsSupported: List<String>? = null,
    @SerialName("require_credential_response_encryption")
    val requireCredentialResponseEncryption: Boolean? = null,
    @SerialName("credentials_supported") val credentialsSupported: List<CredentialSupportedTO> = emptyList(),
    @SerialName("display") val display: List<DisplayTO>? = null,
)

/**
 * Display properties of a supported credential type for a certain language.
 */
@Serializable
internal data class CredentialSupportedDisplayTO(
    @SerialName("name") @Required val name: String,
    @SerialName("locale") val locale: String? = null,
    @SerialName("logo") val logo: LogoObject? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * Logo information.
 */
@Serializable
internal data class LogoObject(
    @SerialName("url") val url: String? = null,
    @SerialName("alt_text") val alternativeText: String? = null,
)

/**
 * The details of a Claim.
 */
@Serializable
internal data class ClaimTO(
    @SerialName("mandatory") val mandatory: Boolean? = null,
    @SerialName("value_type") val valueType: String? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
)

/**
 * Display properties of a Claim.
 */
@Serializable
internal data class DisplayTO(
    @SerialName("name") val name: String? = null,
    @SerialName("locale") val locale: String? = null,
)

/**
 * Default implementation of [CredentialIssuerMetadataResolver].
 */
internal class DefaultCredentialIssuerMetadataResolver(
    private val coroutineDispatcher: CoroutineDispatcher,
    private val ktorHttpClientFactory: KtorHttpClientFactory = HttpClientFactory,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata> = coroutineScope {
        runCatching {
            val credentialIssuerMetadataContent = try {
                val url =
                    URLBuilder(issuer.toString())
                        .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
                        .build()
                        .toURI()
                        .toURL()

                withContext(coroutineDispatcher + CoroutineName("/.well-known/openid-credential-issuer")) {
                    ktorHttpClientFactory().use { client -> client.get(url).body<String>() }
                }
            } catch (t: Throwable) {
                throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
            }

            val credentialIssuerMetadataObject = try {
                Json.decodeFromString<CredentialIssuerMetadataTO>(credentialIssuerMetadataContent)
            } catch (t: Throwable) {
                throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(t)
            }

            val result = credentialIssuerMetadataObject.toDomain().getOrThrow()

            if (result.credentialIssuerIdentifier != issuer) {
                throw InvalidCredentialIssuerId(
                    IllegalArgumentException("credentialIssuerIdentifier does not match expected value"),
                )
            }
            result
        }
    }

    companion object {

        /**
         * Factory which produces a [Ktor Http client][HttpClient]
         * The actual engine will be peeked up by whatever
         * it is available in classpath
         *
         * @see [Ktor Client]("https://ktor.io/docs/client-dependencies.html#engine-dependency)
         */
        val HttpClientFactory: KtorHttpClientFactory = {
            HttpClient {
                install(ContentNegotiation) {
                    json(
                        json = Json { ignoreUnknownKeys = true },
                    )
                }
            }
        }


    }
}

/**
 * Converts and validates  a [CredentialIssuerMetadataTO] as a [CredentialIssuerMetadata] instance.
 */
private fun CredentialIssuerMetadataTO.toDomain(): Result<CredentialIssuerMetadata> = runCatching {
    val credentialIssuerIdentifier = CredentialIssuerId(credentialIssuerIdentifier)
        .getOrThrowAs { InvalidCredentialIssuerId(it) }

    val authorizationServer = authorizationServer
        ?.let { HttpsUrl(it).getOrThrowAs(::InvalidAuthorizationServer) }
        ?: credentialIssuerIdentifier.value

    val credentialEndpoint = CredentialIssuerEndpoint(credentialEndpoint)
        .getOrThrowAs(::InvalidCredentialEndpoint)

    val batchCredentialEndpoint = batchCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(::InvalidBatchCredentialEndpoint) }

    val deferredCredentialEndpoint = deferredCredentialEndpoint
        ?.let { CredentialIssuerEndpoint(it).getOrThrowAs(::InvalidDeferredCredentialEndpoint) }

    val credentialsSupported = try {
        credentialsSupported.map { it.toDomain() }
    } catch (it: Throwable) {
        throw InvalidCredentialsSupported(it)
    }.apply {
        ifEmpty { throw CredentialsSupportedRequired }
    }

    val display = display?.map { it.toDomain() } ?: emptyList()

    CredentialIssuerMetadata(
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

private fun CredentialIssuerMetadataTO.credentialResponseEncryption(): Result<CredentialResponseEncryption> =
    runCatching {
        val requireEncryption = requireCredentialResponseEncryption ?: false
        val encryptionAlgorithms = credentialResponseEncryptionAlgorithmsSupported
            ?.map { JWEAlgorithm.parse(it) }
            ?: emptyList()
        val encryptionMethods = credentialResponseEncryptionMethodsSupported
            ?.map { EncryptionMethod.parse(it) }
            ?: emptyList()

        if (requireEncryption) {
            if (encryptionAlgorithms.isEmpty()) {
                throw CredentialResponseEncryptionAlgorithmsRequired
            }
            val allAreAsymmetricAlgorithms = encryptionAlgorithms.all {
                JWEAlgorithm.Family.ASYMMETRIC.contains(it)
            }
            if (!allAreAsymmetricAlgorithms) {
                throw CredentialResponseAsymmetricEncryptionAlgorithmsRequired
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

/**
 * Converts a [DisplayTO] to a [CredentialIssuerMetadata.Display] instance.
 */
private fun DisplayTO.toDomain(): CredentialIssuerMetadata.Display =
    CredentialIssuerMetadata.Display(name, locale)

private fun <T> Result<T>.getOrThrowAs(f: (Throwable) -> Throwable): T =
    fold(onSuccess = { it }, onFailure = { throw f(it) })
