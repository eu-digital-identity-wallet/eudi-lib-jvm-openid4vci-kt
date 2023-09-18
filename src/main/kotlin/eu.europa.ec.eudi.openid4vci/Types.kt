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
import kotlinx.serialization.json.JsonObject
import java.net.URL

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
    val credentialIssuerIdentifier: CIIdentifier,
    val authorizationServer: String?,
    val credentialEndpoint: URL,
    val batchCredentialEndpoint: URL? = null,
    val deferredCredentialEndpoint: URL? = null,
    val credentialResponseEncryptionAlgValuesSupported: List<String>,
    val credentialResponseEncryptionEncValuesSupported: List<String>,
    val requireCredentialResponseEncryption: Boolean,
    val credentialsSupported: List<CredentialSupported>,
) : java.io.Serializable

typealias CIIdentifier = String

typealias CredentialSupported = String
