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
import java.time.Duration

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
        @SerialName("user_pin_required") val pinRequired: Boolean? = null,
        @SerialName("interval") val interval: Long? = null,
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
 * The data of a supported credentials type.
 */
@Serializable
data class SupportedCredentialObject(
    @SerialName("format") @Required val format: String,
    @SerialName("scope") val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
    @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
) {

    /**
     * Display properties of a supported credential type for a certain language.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") @Required val name: String,
        @SerialName("locale") val locale: String? = null,
        @SerialName("logo") val logo: Logo? = null,
        @SerialName("description") val description: String? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    ) {

        /**
         * Logo information.
         */
        @Serializable
        data class Logo(
            @SerialName("url") val url: String? = null,
            @SerialName("alt_text") val alternativeText: String? = null,
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
 */
@Serializable
data class W3CVerifiableCredentialJsonLdSignedJwtObject(
    @SerialName("format") @Required val format: String,
    @SerialName("scope") val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
    @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
    @SerialName("@context") val context: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
    @SerialName("order") val order: List<String> = emptyList(),
) {

    /**
     * Display properties of a supported credential type for a certain language.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") @Required val name: String,
        @SerialName("locale") val locale: String? = null,
        @SerialName("logo") val logo: Logo? = null,
        @SerialName("description") val description: String? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    ) {

        /**
         * Logo information.
         */
        @Serializable
        data class Logo(
            @SerialName("url") val url: String? = null,
            @SerialName("alt_text") val alternativeText: String? = null,
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
@Serializable
data class W3CVerifiableCredentialSignedJwtObject(
    @SerialName("format") @Required val format: String,
    @SerialName("scope") val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
    @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
    @SerialName("order") val order: List<String> = emptyList(),
) {

    /**
     * Display properties of a supported credential type for a certain language.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") @Required val name: String,
        @SerialName("locale") val locale: String? = null,
        @SerialName("logo") val logo: Logo? = null,
        @SerialName("description") val description: String? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    ) {

        /**
         * Logo information.
         */
        @Serializable
        data class Logo(
            @SerialName("url") val url: String? = null,
            @SerialName("alt_text") val alternativeText: String? = null,
        )
    }
}

/**
 * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
 */
@Serializable
data class W3CVerifiableCredentialsJsonLdDataIntegrityObject(
    @SerialName("format") @Required val format: String,
    @SerialName("type") val type: List<String> = emptyList(),
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
    @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
    @SerialName("scope") val scope: String? = null,
    @SerialName("@context") val context: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
    @SerialName("order") val order: List<String> = emptyList(),
) {

    /**
     * Display properties of a supported credential type for a certain language.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") @Required val name: String,
        @SerialName("locale") val locale: String? = null,
        @SerialName("logo") val logo: Logo? = null,
        @SerialName("description") val description: String? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    ) {

        /**
         * Logo information.
         */
        @Serializable
        data class Logo(
            @SerialName("url") val url: String? = null,
            @SerialName("alt_text") val alternativeText: String? = null,
        )
    }
}

typealias Namespace = String
typealias ClaimName = String

/**
 * The data of a Verifiable Credentials issued as an ISO mDL.
 */
@Serializable
data class MsoMdocObject(
    @SerialName("format") @Required val format: String,
    @SerialName("scope") val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
    @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
    @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
    @SerialName("doctype") @Required val docType: String,
    @SerialName("claims") val claims: Map<Namespace, Map<ClaimName, ClaimObject>> = emptyMap(),
    @SerialName("order") val order: List<String> = emptyList(),
) {

    /**
     * Display properties of a supported credential type for a certain language.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") @Required val name: String,
        @SerialName("locale") val locale: String? = null,
        @SerialName("logo") val logo: Logo? = null,
        @SerialName("description") val description: String? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    ) {

        /**
         * Logo information.
         */
        @Serializable
        data class Logo(
            @SerialName("url") val url: String? = null,
            @SerialName("alt_text") val alternativeText: String? = null,
        )
    }

    /**
     * The details of a Claim.
     */
    @Serializable
    data class ClaimObject(
        @SerialName("mandatory") val mandatory: Boolean? = false,
        @SerialName("value_type") val valueType: String? = null,
        @SerialName("display") val display: List<DisplayObject> = emptyList(),
    ) {

        /**
         * Display properties of a Claim.
         */
        @Serializable
        data class DisplayObject(
            @SerialName("name") val name: String? = null,
            @SerialName("locale") val locale: String? = null,
        )
    }
}

/**
 * Credentials offered in a Credential Offer Request.
 */
sealed interface Credential : java.io.Serializable {

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

        /**
         * An MSO MDOC credential.
         */
        data class MsoMdocCredential(
            val format: MsoMdocObject,
        ) : UnscopedCredential

        /**
         * A W3C Verifiable Credential.
         */
        sealed interface W3CVerifiableCredential : UnscopedCredential {

            /**
             * A signed JWT not using JSON-LD.
             *
             * Format: jwt_vc_json
             */
            data class SignedJwt(val format: W3CVerifiableCredentialSignedJwtObject) : W3CVerifiableCredential

            /**
             * A signed JWT using JSON-LD.
             *
             * Format: jwt_vc_json-ld
             */
            data class JsonLdSignedJwt(val format: W3CVerifiableCredentialJsonLdSignedJwtObject) :
                W3CVerifiableCredential

            /**
             * Data Integrity using JSON-LD.
             *
             * Format: ldp_vc
             */
            data class JsonLdDataIntegrity(val format: W3CVerifiableCredentialsJsonLdDataIntegrityObject) :
                W3CVerifiableCredential
        }

        /**
         * An unknown [UnscopedCredential].
         */
        data class UnknownCredential(
            val format: String,
            val content: JsonObject,
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
        val interval: Duration = Duration.ofSeconds(5L),
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
