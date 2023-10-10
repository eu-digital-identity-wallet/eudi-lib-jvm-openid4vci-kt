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

import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.net.URI

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

typealias CredentialDefinition = JsonObject

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
    @SerialName("credential_response_encryption_alg_values_supported")
    val credentialResponseEncryptionAlgorithmsSupported: List<String>? = null,
    @SerialName("credential_response_encryption_enc_values_supported")
    val credentialResponseEncryptionMethodsSupported: List<String>? = null,
    @SerialName("require_credential_response_encryption")
    val requireCredentialResponseEncryption: Boolean? = null,
    @SerialName("credentials_supported") val credentialsSupported: List<JsonObject> = emptyList(),
    @SerialName("display") val display: List<DisplayObject>? = null,
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
 * The metadata of a Credentials that can be issued by a Credential Issuer.
 */
sealed interface CredentialSupportedObject {

    val format: String
    val scope: String?
    val cryptographicBindingMethodsSupported: List<String>?
    val cryptographicSuitesSupported: List<String>?
    val proofTypesSupported: List<String>?
    val display: List<DisplayObject>?

    /**
     * The data of a W3C Verifiable Credential.
     */
    sealed interface W3CVerifiableCredentialCredentialSupportedObject : CredentialSupportedObject {

        val credentialDefinition: JsonObject
        val order: List<String>?

        /**
         * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
         */
        @Serializable
        data class W3CVerifiableCredentialSignedJwtCredentialSupportedObject(
            @SerialName("format") @Required override val format: String,
            @SerialName("scope") override val scope: String? = null,
            @SerialName("cryptographic_binding_methods_supported")
            override val cryptographicBindingMethodsSupported: List<String>? = null,
            @SerialName("cryptographic_suites_supported")
            override val cryptographicSuitesSupported: List<String>? = null,
            @SerialName("proof_types_supported")
            override val proofTypesSupported: List<String>? = null,
            @SerialName("display") override val display: List<DisplayObject>? = null,
            @SerialName("credential_definition") @Required override val credentialDefinition: JsonObject,
            @SerialName("order") override val order: List<String>? = null,
        ) : W3CVerifiableCredentialCredentialSupportedObject {
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
            @SerialName("cryptographic_binding_methods_supported")
            override val cryptographicBindingMethodsSupported: List<String>? = null,
            @SerialName("cryptographic_suites_supported")
            override val cryptographicSuitesSupported: List<String>? = null,
            @SerialName("proof_types_supported")
            override val proofTypesSupported: List<String>? = null,
            @SerialName("display") override val display: List<DisplayObject>? = null,
            @SerialName("@context") @Required val context: List<String> = emptyList(),
            @SerialName("credential_definition") @Required override val credentialDefinition: JsonObject,
            @SerialName("order") override val order: List<String>? = null,
        ) : W3CVerifiableCredentialCredentialSupportedObject {
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
            @SerialName("cryptographic_binding_methods_supported")
            override val cryptographicBindingMethodsSupported: List<String>? = null,
            @SerialName("cryptographic_suites_supported")
            override val cryptographicSuitesSupported: List<String>? = null,
            @SerialName("proof_types_supported")
            override val proofTypesSupported: List<String>? = null,
            @SerialName("display") override val display: List<DisplayObject>? = null,
            @SerialName("@context") @Required val context: List<String> = emptyList(),
            @SerialName("type") @Required val type: List<String> = emptyList(),
            @SerialName("credential_definition") @Required override val credentialDefinition: JsonObject,
            @SerialName("order") override val order: List<String>? = null,
        ) : W3CVerifiableCredentialCredentialSupportedObject {
            init {
                require(format == "ldp_vc") { "invalid format '$format'" }
            }
        }
    }

    /**
     * The data of a Verifiable Credentials issued as an ISO mDL.
     */
    @Serializable
    data class MsoMdocCredentialCredentialSupportedObject(
        @SerialName("format") @Required override val format: String,
        @SerialName("scope") override val scope: String? = null,
        @SerialName("cryptographic_binding_methods_supported")
        override val cryptographicBindingMethodsSupported: List<String>? = null,
        @SerialName("cryptographic_suites_supported")
        override val cryptographicSuitesSupported: List<String>? = null,
        @SerialName("proof_types_supported")
        override val proofTypesSupported: List<String>? = null,
        @SerialName("display") override val display: List<DisplayObject>? = null,
        @SerialName("doctype") @Required val docType: String,
        @SerialName("claims") val claims: Map<String, Map<String, ClaimObject>>? = null,
        @SerialName("order") val order: List<String>? = null,
    ) : CredentialSupportedObject {
        init {
            require(format == "mso_mdoc") { "invalid format '$format'" }
        }

        /**
         * The details of a Claim.
         */
        @Serializable
        data class ClaimObject(
            @SerialName("mandatory") val mandatory: Boolean? = null,
            @SerialName("value_type") val valueType: String? = null,
            @SerialName("display") val display: List<DisplayObject>? = null,
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

data class PKCEVerifier(
    val codeVerifier: String,
    val codeVerifierMethod: String,
) {
    init {
        require(codeVerifier.isNotEmpty()) { "Code verifier must not be empty" }
        require(codeVerifierMethod.isNotEmpty()) { "Code verifier method must not be empty" }
    }
}

data class IssuanceAccessToken(
    val accessToken: String,
) {
    init {
        require(accessToken.isNotEmpty()) { "Access Token must not be empty" }
    }
}

data class IssuedCertificate(
    val format: String,
    val content: String,
)

sealed interface IssuanceAuthorization {

    data class AuthorizationCode(
        val authorizationCode: String,
    ) : IssuanceAuthorization {
        init {
            require(authorizationCode.isNotEmpty()) { "Authorization code must not be empty" }
        }
    }

    data class PreAuthorizationCode(
        val preAuthorizedCode: String,
        val pin: String,
    ) : IssuanceAuthorization {
        init {
            require(preAuthorizedCode.isNotEmpty()) { "Pre-Authorization code must not be empty" }
        }
    }
}

typealias CIAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata
