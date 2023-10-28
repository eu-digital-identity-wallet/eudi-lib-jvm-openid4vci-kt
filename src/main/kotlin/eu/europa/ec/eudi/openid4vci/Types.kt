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

import com.nimbusds.jwt.JWT
import com.nimbusds.oauth2.sdk.`as`.ReadOnlyAuthorizationServerMetadata
import io.ktor.client.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
data class CredentialOfferRequestTO(
    @SerialName("credential_issuer") @Required val credentialIssuerIdentifier: String,
    @SerialName("credentials") @Required val credentials: List<JsonElement>,
    @SerialName("grants") val grants: GrantsTO? = null,
)

/**
 * Data of the Grant Types the Credential Issuer is prepared to process for a Credential Offer.
 */
@Serializable
data class GrantsTO(
    @SerialName("authorization_code") val authorizationCode: AuthorizationCodeTO? = null,
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code") val preAuthorizedCode: PreAuthorizedCodeTO? = null,
) {

    /**
     * Data for an Authorization Code Grant Type.
     */
    @Serializable
    data class AuthorizationCodeTO(
        @SerialName("issuer_state") val issuerState: String? = null,
    )

    /**
     * Data for a Pre-Authorized Code Grant Type.
     */
    @Serializable
    data class PreAuthorizedCodeTO(
        @SerialName("pre-authorized_code") @Required val preAuthorizedCode: String,
        @SerialName("user_pin_required") val pinRequired: Boolean? = null,
        @SerialName("interval") val interval: Long? = null,
    )
}

/**
 * Unvalidated metadata of a Credential Issuer.
 */
@Serializable
data class CredentialIssuerMetadataTO(
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
    @SerialName("display") val display: List<DisplayTO>? = null,
) {

    /**
     * Display properties of a Credential Issuer.
     */
    @Serializable
    data class DisplayTO(
        @SerialName("name") val name: String? = null,
        @SerialName("locale") val locale: String? = null,
    )
}

/**
 * The metadata of a Credentials that can be issued by a Credential Issuer.
 */
sealed interface CredentialSupportedTO {

    val format: String
    val scope: String?
    val cryptographicBindingMethodsSupported: List<String>?
    val cryptographicSuitesSupported: List<String>?
    val proofTypesSupported: List<String>?
    val display: List<DisplayTO>?

    fun toDomain(): CredentialSupported
}

/**
 * The details of a Claim.
 */
@Serializable
data class ClaimTO(
    @SerialName("mandatory") val mandatory: Boolean? = null,
    @SerialName("value_type") val valueType: String? = null,
    @SerialName("display") val display: List<DisplayTO>? = null,
) {

    /**
     * Display properties of a Claim.
     */
    @Serializable
    data class DisplayTO(
        @SerialName("name") val name: String? = null,
        @SerialName("locale") val locale: String? = null,
    )
}

/**
 * Display properties of a supported credential type for a certain language.
 */
@Serializable
data class DisplayTO(
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
        val pin: String?,
    ) : IssuanceAuthorization {
        init {
            require(preAuthorizedCode.isNotEmpty()) { "Pre-Authorization code must not be empty" }
        }
    }
}

data class CNonce(
    val value: String,
    val expiresInSeconds: Long? = 5,
) {
    init {
        require(value.isNotEmpty()) { "Value cannot be empty" }
    }
}

sealed interface Proof {
    fun type(): ProofType
    fun toJsonObject(): JsonObject

    data class Jwt(
        val jwt: JWT,
    ) : Proof {
        override fun type() = ProofType.JWT
        override fun toJsonObject(): JsonObject =
            JsonObject(
                mapOf(
                    "proof_type" to JsonPrimitive("jwt"),
                    "jwt" to JsonPrimitive(jwt.serialize()),
                ),
            )
    }

    data class Cwt(
        val cwt: String,
    ) : Proof {
        override fun type() = ProofType.CWT
        override fun toJsonObject(): JsonObject =
            JsonObject(
                mapOf(
                    "proof_type" to JsonPrimitive("cwt"),
                    "jwt" to JsonPrimitive(cwt),
                ),
            )
    }
}

@JvmInline
value class Scope private constructor(
    val value: String,
) {
    companion object {
        fun of(value: String): Scope {
            require(value.isNotEmpty()) { "Scope value cannot be empty" }
            return Scope(value)
        }
    }
}

typealias KtorHttpClientFactory = () -> HttpClient

typealias CIAuthorizationServerMetadata = ReadOnlyAuthorizationServerMetadata
