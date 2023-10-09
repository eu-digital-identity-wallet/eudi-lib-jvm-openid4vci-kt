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
import eu.europa.ec.eudi.openid4vci.internal.credentialoffer.DefaultCredentialIssuerMetadataResolver
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import java.util.*

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
    val credentialsSupported: List<CredentialSupported>,
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

typealias Namespace = String
typealias ClaimName = String
typealias MsoMdocClaims = Map<Namespace, Map<ClaimName, CredentialSupported.MsoMdocCredentialCredentialSupported.Claim>>

/**
 * Credentials supported by an Issuer.
 */
sealed interface CredentialSupported : java.io.Serializable {

    val scope: String?
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val cryptographicSuitesSupported: List<String>
    val proofTypesSupported: List<ProofType>
    val display: List<Display>

    /**
     * The data of a W3C Verifiable Credential.
     */
    sealed interface W3CVerifiableCredentialCredentialSupported : CredentialSupported {

        val credentialDefinition: CredentialDefinition
        val order: List<ClaimName>

        /**
         * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
         */
        data class W3CVerifiableCredentialSignedJwtCredentialSupported(
            override val scope: String? = null,
            override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
            override val cryptographicSuitesSupported: List<String> = emptyList(),
            override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
            override val display: List<Display> = emptyList(),
            override val credentialDefinition: CredentialDefinition,
            override val order: List<ClaimName> = emptyList(),
        ) : W3CVerifiableCredentialCredentialSupported

        /**
         * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
         */
        data class W3CVerifiableCredentialJsonLdSignedJwtCredentialSupported(
            override val scope: String? = null,
            override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
            override val cryptographicSuitesSupported: List<String> = emptyList(),
            override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
            override val display: List<Display> = emptyList(),
            val context: List<String> = emptyList(),
            override val credentialDefinition: CredentialDefinition,
            override val order: List<ClaimName> = emptyList(),
        ) : W3CVerifiableCredentialCredentialSupported

        /**
         * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
         */
        data class W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported(
            override val scope: String? = null,
            override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
            override val cryptographicSuitesSupported: List<String> = emptyList(),
            override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
            override val display: List<Display> = emptyList(),
            val context: List<String> = emptyList(),
            val type: List<String> = emptyList(),
            override val credentialDefinition: CredentialDefinition,
            override val order: List<ClaimName> = emptyList(),
        ) : W3CVerifiableCredentialCredentialSupported
    }

    /**
     * The data of a Verifiable Credentials issued as an ISO mDL.
     */
    data class MsoMdocCredentialCredentialSupported(
        override val scope: String? = null,
        override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
        override val cryptographicSuitesSupported: List<String> = emptyList(),
        override val proofTypesSupported: List<ProofType> = listOf(ProofType.JWT),
        override val display: List<Display> = emptyList(),
        val docType: String,
        val claims: MsoMdocClaims = emptyMap(),
        val order: List<ClaimName> = emptyList(),
    ) : CredentialSupported {

        /**
         * The details of a Claim.
         */
        data class Claim(
            val mandatory: Boolean? = false,
            val valueType: String? = null,
            val display: List<Display> = emptyList(),
        ) : java.io.Serializable {

            /**
             * Display properties of a Claim.
             */
            data class Display(
                val name: String? = null,
                val locale: Locale? = null,
            ) : java.io.Serializable
        }
    }
}

/**
 * Cryptographic Binding Methods for issued Credentials.
 */
sealed interface CryptographicBindingMethod : java.io.Serializable {

    /**
     * JWK format.
     */
    object JWK : CryptographicBindingMethod {
        private fun readResolve(): Any = JWK
        override fun toString(): String = "JWK"
    }

    /**
     * COSE Key object.
     */
    object COSE : CryptographicBindingMethod {
        private fun readResolve(): Any = COSE
        override fun toString(): String = "COSE"
    }

    /**
     * MSO.
     */
    object MSO : CryptographicBindingMethod {
        private fun readResolve(): Any = MSO
        override fun toString(): String = "MSO"
    }

    /**
     * DID method.
     */
    data class DID(
        val method: String,
    ) : CryptographicBindingMethod
}

/**
 * Proof types supported by a Credential Issuer.
 */
enum class ProofType : java.io.Serializable {
    JWT,
    CWT,
}

typealias CssColor = String

/**
 * Display properties of a supported credential type for a certain language.
 */
data class Display(
    val name: String,
    val locale: Locale? = null,
    val logo: Logo? = null,
    val description: String? = null,
    val backgroundColor: CssColor? = null,
    val textColor: CssColor? = null,
) : java.io.Serializable {

    /**
     * Logo information.
     */
    data class Logo(
        val url: HttpsUrl? = null,
        val alternativeText: String? = null,
    ) : java.io.Serializable
}

/**
 * Service for fetching, parsing, and validating the metadata of a Credential Issuer.
 */
internal fun interface CredentialIssuerMetadataResolver {

    /**
     * Tries to fetch and validate the metadata of a Credential Issuer.
     */
    suspend fun resolve(issuer: CredentialIssuerId): Result<CredentialIssuerMetadata>

    companion object {

        /**
         * Creates a new [CredentialIssuerMetadataResolver] instance.
         *
         * [httpGet] execution are dispatched on [ioCoroutineDispatcher].
         */
        operator fun invoke(
            ioCoroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpGet: HttpGet<String>,
        ): CredentialIssuerMetadataResolver = DefaultCredentialIssuerMetadataResolver(ioCoroutineDispatcher, httpGet)
    }
}
