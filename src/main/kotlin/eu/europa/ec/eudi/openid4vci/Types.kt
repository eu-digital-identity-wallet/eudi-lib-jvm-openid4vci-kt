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

import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI
import java.net.URL

typealias JsonString = String

/**
 * A [URI] that strictly uses the 'https' protocol.
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

/**
 * The unvalidated data of a Credential Offer.
 */
@Serializable
data class CredentialOfferRequestObject(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("credentials") @Required val credentials: List<JsonElement>,
    @SerialName("grants") val grants: GrantsObject? = null,
)

/**
 * Data of the Grant Types the Credential Issuer is prepared to process for a Credential Offer.
 */
@Serializable
data class GrantsObject(
    @SerialName("authorization_code") val authorizationCode: AuthorizationCodeObject? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: PreAuthorizedCodeObject? = null,
) {

    /**
     * Data for an Authorization Code Grant Type.
     */
    @Serializable
    data class AuthorizationCodeObject(
        @SerialName("issuer_state") val issuerState: String? = null,
    )

    /**
     * Data for a Pre-Authorized Code Grant Type.
     */
    @Serializable
    data class PreAuthorizedCodeObject(
        @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
        @SerialName("user_pin_required") val userPinRequired: Boolean? = null,
    )
}

/**
 * A Credential Offer.
 */
data class CredentialOffer(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val credentials: List<Credential>,
    val grants: Grants? = null,
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

/**
 * Credentials offered in a Credential Offer Request.
 */
sealed interface Credential {

    /**
     * A Credential identified by its Scope.
     */
    data class ScopedCredential(
        val scope: String,
    ) : Credential

    /**
     * A Credential format not identified by a Scope.
     */
    sealed interface UnscopedCredential : Credential {

        val format: String

        /**
         * An MSO MDOC credential.
         */
        data class MsoMdocCredential(
            override val format: String,
            val docType: String,
        ) : UnscopedCredential

        /**
         * A W3C Verifiable Credential.
         */
        data class W3CVerifiableCredential(
            override val format: String,
            val credentialDefinition: String,
        ) : UnscopedCredential
    }
}

/**
 * The Grant Types a Credential Issuer can process for a Credential Offer.
 */
sealed interface Grants : java.io.Serializable {

    /**
     * Data for an Authorization Code Grant.
     */
    data class AuthorizationCode(
        val issuerState: String? = null,
    ) : Grants

    /**
     * Data for a Pre-Authorized Code Grant.
     */
    data class PreAuthorizedCode(
        val preAuthorizedCode: String,
        val pinRequired: Boolean = false,
    ) : Grants

    /**
     * Data for either an Authorization Code Grant or a Pre-Authorized Code Grant.
     */
    data class Both(
        val authorizationCode: AuthorizationCode,
        val preAuthorizedCode: PreAuthorizedCode,
    ) : Grants
}

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

typealias CredentialSupported = String
