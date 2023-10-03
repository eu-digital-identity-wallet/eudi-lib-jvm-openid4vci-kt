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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI
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
 * An MSO MDOC Credential Object.
 */
@Serializable
data class MsoMdocCredentialObject(
    @SerialName("format") @Required val format: String,
    @SerialName("doctype") @Required val docType: String,
)

/**
 * A W3C Verifiable Credential, Credential Object.
 */
@Serializable
data class W3CVerifiableCredentialCredentialObject(
    @SerialName("format") @Required val format: String,
    @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
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
    val credentialIssuerMetadata: CredentialIssuerMetadata,
    val credentials: List<OfferedCredential>,
    val grants: Grants? = null,
) : java.io.Serializable {
    init {
        require(credentials.isNotEmpty()) { "credentials must not be empty" }
    }
}

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

typealias CredentialDefinition = JsonObject

/**
 * A Credential being offered in a Credential Offer.
 */
sealed interface OfferedCredential : java.io.Serializable {

    val scope: String?

    /**
     * An MSO MDOC credential.
     */
    data class MsoMdocCredential(
        val docType: String,
        override val scope: String? = null,
    ) : OfferedCredential

    /**
     * A W3C Verifiable Credential.
     */
    sealed interface W3CVerifiableCredential : OfferedCredential {

        /**
         * A signed JWT not using JSON-LD.
         *
         * Format: jwt_vc_json
         */
        data class SignedJwt(
            val credentialDefinition: CredentialDefinition,
            override val scope: String? = null,
        ) : W3CVerifiableCredential

        /**
         * A signed JWT using JSON-LD.
         *
         * Format: jwt_vc_json-ld
         */
        data class JsonLdSignedJwt(
            val credentialDefinition: CredentialDefinition,
            override val scope: String? = null,
        ) : W3CVerifiableCredential

        /**
         * Data Integrity using JSON-LD.
         *
         * Format: ldp_vc
         */
        data class JsonLdDataIntegrity(
            val credentialDefinition: CredentialDefinition,
            override val scope: String? = null,
        ) : W3CVerifiableCredential
    }
}

/**
 * The Grant Types a Credential Issuer can process for a Credential Offer.
 */
sealed interface Grants : java.io.Serializable {

    /**
     * Data for an Authorization Code Grant. [issuerState], if provided, must not be blank.
     */
    data class AuthorizationCode(
        val issuerState: String? = null,
    ) : Grants {
        init {
            require(!(issuerState?.isBlank() ?: false)) { "issuerState cannot be blank" }
        }
    }

    /**
     * Data for a Pre-Authorized Code Grant. [preAuthorizedCode] must not be blank.
     */
    data class PreAuthorizedCode(
        val preAuthorizedCode: String,
        val pinRequired: Boolean = false,
        val interval: Duration = Duration.ofSeconds(5L),
    ) : Grants {
        init {
            require(preAuthorizedCode.isNotBlank()) { "preAuthorizedCode cannot be blank" }
        }
    }

    /**
     * Data for either an Authorization Code Grant or a Pre-Authorized Code Grant.
     */
    data class Both(
        val authorizationCode: AuthorizationCode,
        val preAuthorizedCode: PreAuthorizedCode,
    ) : Grants
}

/**
 * Unvalidated metadata of a Credential Issuer.
 */
@Serializable
data class CredentialIssuerMetadataObject(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("authorization_server") val authorizationServer: String? = null,
    @SerialName("credential_endpoint") @Required val credentialEndpoint: String,
    @SerialName("batch_credential_endpoint") val batchCredentialEndpoint: String? = null,
    @SerialName("deferred_credential_endpoint") val deferredCredentialEndpoint: String? = null,
    @SerialName("credential_response_encryption_alg_values_supported") val credentialResponseEncryptionAlgorithmsSupported: List<String> =
        emptyList(),
    @SerialName("credential_response_encryption_enc_values_supported") val credentialResponseEncryptionMethodsSupported: List<String> =
        emptyList(),
    @SerialName("require_credential_response_encryption") val requireCredentialResponseEncryption: Boolean? = null,
    @SerialName("credentials_supported") val credentialsSupported: List<JsonObject> = emptyList(),
    @SerialName("display") val display: List<DisplayObject> = emptyList(),
) {

    /**
     * Display properties of a Credential Issuer.
     */
    @Serializable
    data class DisplayObject(
        @SerialName("name") val name: String? = null,
        @SerialName("locale") val locale: String? = null,
    )
}

/**
 * The metadata of a Credential Issuer.
 */
data class CredentialIssuerMetadata(
    val credentialIssuerIdentifier: CredentialIssuerId,
    val authorizationServer: HttpsUrl = credentialIssuerIdentifier.value,
    val credentialEndpoint: CredentialIssuerEndpoint,
    val batchCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val deferredCredentialEndpoint: CredentialIssuerEndpoint? = null,
    val credentialResponseEncryptionAlgorithmsSupported: List<JWEAlgorithm> = emptyList(),
    val credentialResponseEncryptionMethodsSupported: List<EncryptionMethod> = emptyList(),
    val requireCredentialResponseEncryption: Boolean = false,
    val credentialsSupported: List<CredentialSupportedObject>,
    val display: List<Display> = emptyList(),
) : java.io.Serializable {
    init {
        if (requireCredentialResponseEncryption) {
            require(credentialResponseEncryptionAlgorithmsSupported.isNotEmpty()) {
                "credentialResponseEncryptionAlgorithmsSupported are required"
            }
        }
        require(credentialsSupported.isNotEmpty()) { "credentialsSupported must not be empty" }
    }

    /**
     * The display properties of the Credential Issuer.
     */
    data class Display(
        val name: String? = null,
        val locale: String? = null,
    ) : java.io.Serializable
}

/**
 * An endpoint of a Credential Issuer. It's an [HttpsUrl] that must not have a fragment.
 */
@JvmInline
value class CredentialIssuerEndpoint private constructor(val value: HttpsUrl) {

    companion object {

        /**
         * Parses the provided [value] as an [HttpsUrl] and tries to create a [CredentialIssuerEndpoint].
         */
        operator fun invoke(value: String): Result<CredentialIssuerEndpoint> =
            HttpsUrl(value)
                .mapCatching {
                    require(it.value.fragment.isNullOrBlank()) { "CredentialIssuerEndpoint must not have a fragment" }
                    CredentialIssuerEndpoint(it)
                }
    }
}

/**
 * The metadata of a Credentials that can be issued by a Credential Issuer.
 */
sealed interface CredentialSupportedObject {

    /**
     * The format of the supported credential.
     */
    val format: String

    /**
     * The scope of a supported credential.
     */
    val scope: String?

    /**
     * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
     */
    @Serializable
    data class W3CVerifiableCredentialSignedJwtCredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
        @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
        @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
        @SerialName("display") val display: List<DisplayObject> = emptyList(),
        @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
        @SerialName("order") val order: List<String> = emptyList(),
    ) : CredentialSupportedObject {
        init {
            require(format == "jwt_vc_json") { "invalid format '$format'" }
        }
    }

    /**
     * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
     */
    @Serializable
    data class W3CVerifiableCredentialJsonLdSignedJwtCredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
        @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
        @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
        @SerialName("display") val display: List<DisplayObject> = emptyList(),
        @SerialName("@context") val context: List<String> = emptyList(),
        @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
        @SerialName("order") val order: List<String> = emptyList(),
    ) : CredentialSupportedObject {
        init {
            require(format == "jwt_vc_json-ld") { "invalid format '$format'" }
        }
    }

    /**
     * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
     */
    @Serializable
    data class W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
        @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
        @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
        @SerialName("display") val display: List<DisplayObject> = emptyList(),
        @SerialName("@context") val context: List<String> = emptyList(),
        @SerialName("type") val type: List<String> = emptyList(),
        @SerialName("credential_definition") @Required val credentialDefinition: JsonObject,
        @SerialName("order") val order: List<String> = emptyList(),
    ) : CredentialSupportedObject {
        init {
            require(format == "ldp_vc") { "invalid format '$format'" }
        }
    }

    /**
     * The data of a Verifiable Credentials issued as an ISO mDL.
     */
    @Serializable
    data class MsoMdocCredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported") val cryptographicBindingMethodsSupported: List<String> = emptyList(),
        @SerialName("cryptographic_suites_supported") val cryptographicSuitesSupported: List<String> = emptyList(),
        @SerialName("proof_types_supported") val proofTypesSupported: List<String> = emptyList(),
        @SerialName("display") val display: List<DisplayObject> = emptyList(),
        @SerialName("doctype") @Required val docType: String,
        @SerialName("claims") val claims: Map<String, Map<String, ClaimObject>> = emptyMap(),
        @SerialName("order") val order: List<String> = emptyList(),
    ) : CredentialSupportedObject {
        init {
            require(format == "mso_mdoc") { "invalid format '$format'" }
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
}

/**
 * Display properties of a supported credential type for a certain language.
 */
@Serializable
data class DisplayObject(
    @SerialName("name") @Required val name: String,
    @SerialName("locale") val locale: String? = null,
    @SerialName("logo") val logo: LogoObject? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
) {

    /**
     * Logo information.
     */
    @Serializable
    data class LogoObject(
        @SerialName("url") val url: String? = null,
        @SerialName("alt_text") val alternativeText: String? = null,
    )
}
