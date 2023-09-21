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
package eu.europa.ec.eudi.openid4vci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.net.URL
import java.time.Duration

typealias Json = String

/**
 * A [URL] that strictly uses the 'https' protocol.
 */
@JvmInline
value class HttpsUrl private constructor(val value: URI) {

    companion object {

        /**
         * Parses the provided [value] as a [URI] and tries creates a new [HttpsUrl].
         */
        operator fun invoke(value: String): Result<HttpsUrl> = runCatching {
            val uri = URI.create(value)
            require(uri.scheme.contentEquals("https", true)) { "URL must use https protocol" }
            HttpsUrl(uri)
        }
    }
}

@Serializable
data class UnvalidatedCredentialOffer(
    @SerialName("credential_issuer") val credentialIssuerIdentifier: String,
    @SerialName("credentials") val credentials: List<JsonElement>,
    @SerialName("grants") val grants: List<JsonObject>,
)

data class ResolvedCredentialOffer(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val credentials: List<Credential>,
    val grants: GrantType,
)

@Serializable
data class UnvalidatedCredentialIssuerMetaData(
    @SerialName("credential_issuer") val credentialIssuerIdentifier: String,
    @SerialName("authorization_server") val authorizationServer: String? = null,
    @SerialName("credential_endpoint") val credentialEndpoint: String,
    @SerialName("batch_credential_endpoint") val batchCredentialEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("credential_response_encryption_alg_values_supported") val credentialResponseEncryptionAlgValuesSupported: List<String>,
    @SerialName("credential_response_encryption_enc_values_supported") val credentialResponseEncryptionEncValuesSupported: List<String>,
    @SerialName("require_credential_response_encryption") val requireCredentialResponseEncryption: Boolean,
    @SerialName("credentials_supported") val credentialsSupported: List<UnvalidatedCredentialSupported>,
) : java.io.Serializable

@Serializable
data class UnvalidatedCredentialSupported(
    @SerialName("format") val format: String,
    @SerialName("scope") val scope: String?,
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String>,
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String>,
    @SerialName("proof_types_supported") val proofTypesSupported: List<String>,
    @SerialName("display") val display: List<JsonObject>,
)

data class CredentialIssuerMetaData(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val authorizationServer: String?,
    val credentialEndpoint: URL,
    val batchCredentialEndpoint: URL? = null,
    val deferredCredentialEndpoint: URL? = null,
    val credentialResponseEncryptionAlgValuesSupported: List<String>,
    val credentialResponseEncryptionEncValuesSupported: List<String>,
    val requireCredentialResponseEncryption: Boolean,
    val credentialsSupported: List<CredentialSupported>,
) : java.io.Serializable

/**
 * The Id of a Credential Issuer. An [HttpsUrl] that has no fragment or query parameters.
 */
@JvmInline
value class CredentialIssuerId private constructor(val value: HttpsUrl) {

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerId].
         */
        operator fun invoke(value: String): Result<CredentialIssuerId> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.fragment.isNullOrBlank()) { "CredentialIssuerId must not have a fragment" }
                    require(it.value.query.isNullOrBlank()) { "CredentialIssuerId must not have query parameters " }
                    CredentialIssuerId(it)
                }
    }
}

typealias CredentialSupported = String

sealed interface GrantType {
    data class AuthorizationCode(
        val code: String,
        val issuerState: String? = null,
    ) : GrantType

    data class PreAuthorizedCode(
        val preAuthorizedCode: String,
        val pinRequired: Boolean,
        val interval: Duration = Duration.ofSeconds(5L),
    ) : GrantType

    data class Both(val authorizationCode: AuthorizationCode, val preAuthorizedCode: PreAuthorizedCode) : GrantType
}

sealed interface Credential {

    data class ScopedCredential(
        val scope: String,
    ) : Credential

    sealed interface UnscopedCredential : Credential {

        val format: String

        data class MsoMdocCredential(
            override val format: String,
            val docType: String,
        ) : UnscopedCredential

        data class W3CVerifiableCredential(
            override val format: String,
            val credentialDefinition: String,
        ) : UnscopedCredential
    }
}
