/*
 * Copyright (c) 2023-2026 European Commission
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

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.openid4vci.internal.LocaleSerializer
import kotlinx.serialization.SerialName
import java.io.Serializable
import java.net.URI
import java.net.URL
import java.util.*

/**
 * Cryptographic Binding Methods for issued Credentials.
 */
sealed interface CryptographicBindingMethod : Serializable {

    /**
     * JWK format.
     */
    data object JWK : CryptographicBindingMethod {
        private fun readResolve(): Any = JWK
    }

    /**
     * COSE Key object.
     */
    data object COSE : CryptographicBindingMethod {
        private fun readResolve(): Any = COSE
    }

    /**
     * DID method.
     */
    data class DID(val method: String) : CryptographicBindingMethod

    /**
     * Other format
     */
    data class Other(val value: String) : CryptographicBindingMethod
}

/**
 * Proof types supported by a Credential Issuer.
 */
enum class ProofType : Serializable {
    JWT,
    ATTESTATION,
}

sealed interface ProofTypeMeta : Serializable {
    data class Jwt(
        val algorithms: List<JWSAlgorithm>,
        val keyAttestationConstraints: KeyAttestationConstraints,
    ) : ProofTypeMeta {
        init {
            require(algorithms.isNotEmpty()) { "Supported algorithms in case of JWT cannot be empty" }
        }
    }

    data class Attestation(
        val algorithms: List<JWSAlgorithm>,
        val keyAttestationConstraints: KeyAttestationConstraints,
    ) : ProofTypeMeta {
        init {
            require(algorithms.isNotEmpty()) { "Supported algorithms in case of Attestation cannot be empty" }
        }
    }
}

/**
 * The constraints of the Key Attestation of a JWT Proof, or Attestation Proof.
 */
data class KeyAttestationConstraints(
    val keyStorage: List<String>?,
    val userAuthentication: List<String>?,
) : Serializable {
    init {
        if (keyStorage != null) {
            require(keyStorage.isNotEmpty()) {
                "Key storage constraints, if provided, should be non-empty"
            }
        }
        if (userAuthentication != null) {
            require(userAuthentication.isNotEmpty()) {
                "User authentication constraints, if provided, should be non-empty"
            }
        }
    }

    val hasConstrains: Boolean
        get() = userAuthentication != null || keyStorage != null

    companion object {
        val None: KeyAttestationConstraints get() = KeyAttestationConstraints(null, null)
    }
}

val KeyAttestationConstraints.keyStorageOrDefault: List<String>
    get() = keyStorage.orEmpty()

val KeyAttestationConstraints.userAuthenticationOrDefault: List<String>
    get() = userAuthentication.orEmpty()

val ProofTypeMeta.type: ProofType
    get() = when (this) {
        is ProofTypeMeta.Jwt -> ProofType.JWT
        is ProofTypeMeta.Attestation -> ProofType.ATTESTATION
    }

val ProofTypeMeta.algorithms: List<JWSAlgorithm>
    get() = when (this) {
        is ProofTypeMeta.Jwt -> algorithms
        is ProofTypeMeta.Attestation -> algorithms
    }

@JvmInline
value class ProofTypesSupported private constructor(val values: Set<ProofTypeMeta>) {

    operator fun get(type: ProofType): ProofTypeMeta? = values.firstOrNull { it.type == type }

    companion object {
        val Empty: ProofTypesSupported = ProofTypesSupported(emptySet())

        operator fun invoke(values: Set<ProofTypeMeta>): ProofTypesSupported {
            require(values.groupBy { it.type }.all { (_, instances) -> instances.size == 1 }) {
                "Multiple instance of the same proof type are not allowed"
            }
            return ProofTypesSupported(values)
        }
    }
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
    val backgroundImage: URI? = null,
    val textColor: CssColor? = null,
) : Serializable {

    /**
     * Logo information.
     */
    data class Logo(
        val uri: URI? = null,
        val alternativeText: String? = null,
    ) : Serializable
}

data class CredentialMetadata(
    val display: List<Display>? = emptyList(),
    val claims: List<Claim>? = emptyList(),
)

/**
 * Credentials supported by an Issuer.
 */
sealed interface CredentialConfiguration : Serializable {
    val scope: String?
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val proofTypesSupported: ProofTypesSupported
    val credentialMetadata: CredentialMetadata?
}

/**
 * The details of a Claim.
 */
@kotlinx.serialization.Serializable
data class Claim(
    @SerialName("path") val path: ClaimPath,
    @SerialName("mandatory") val mandatory: Boolean? = false,
    @SerialName("display") val display: List<Display> = emptyList(),
) : Serializable {

    /**
     * Display properties of a Claim.
     */
    @kotlinx.serialization.Serializable
    data class Display(
        @SerialName("name") val name: String? = null,
        @kotlinx.serialization.Serializable(LocaleSerializer::class)
        @SerialName("locale") val locale: Locale? = null,
    ) : Serializable
}

/**
 * COSE Algorithm value.
 *
 * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml">CBOR Object Signing and Encryption (COSE)</a>
 */
@JvmInline
value class CoseAlgorithm(val value: Int) : Serializable {
    override fun toString(): String = value.toString()
}

/**
 * The data of a Verifiable Credentials issued as an ISO MDOC.
 */
data class MsoMdocCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    val credentialSigningAlgorithmsSupported: List<CoseAlgorithm> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val credentialMetadata: CredentialMetadata?,
    val docType: String,
) : CredentialConfiguration

/**
 * JWS Algorithm Name
 *
 * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml">JSON Object Signing and Encryption (JOSE)</a>
 */
@JvmInline
value class JwsAlgorithm(val name: String) : Serializable {
    override fun toString(): String = name
}

/**
 * The data of a Verifiable Credentials issued as an SD-JWT VC.
 */
data class SdJwtVcCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    val credentialSigningAlgorithmsSupported: List<JwsAlgorithm> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val credentialMetadata: CredentialMetadata?,
    val type: String,
) : CredentialConfiguration

data class W3CJsonLdCredentialDefinition(
    val context: List<URL>,
    val type: List<String>,
)

/**
 * Linked Data Algorithm Identifier
 *
 * @see <a href="https://w3c-ccg.github.io/ld-cryptosuite-registry/">Linked Data Cryptographic Suite Registry</a>
 */
@JvmInline
value class LinkedDataAlgorithm(val identifier: String) : Serializable {
    override fun toString(): String = identifier
}

/**
 * The data of a W3C Verifiable Credential issued using Data Integrity and JSON-LD.
 */
data class W3CJsonLdDataIntegrityCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    val credentialSigningAlgorithmsSupported: List<LinkedDataAlgorithm> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val credentialMetadata: CredentialMetadata?,
    val credentialDefinition: W3CJsonLdCredentialDefinition,
) : CredentialConfiguration

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
 */
data class W3CJsonLdSignedJwtCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    val credentialSigningAlgorithmsSupported: List<LinkedDataAlgorithm> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val credentialMetadata: CredentialMetadata?,
    val credentialDefinition: W3CJsonLdCredentialDefinition,
) : CredentialConfiguration

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
data class W3CSignedJwtCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    val credentialSigningAlgorithmsSupported: List<JwsAlgorithm> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val credentialMetadata: CredentialMetadata?,
    val credentialDefinition: CredentialDefinition,
) : CredentialConfiguration {

    data class CredentialDefinition(
        val type: List<String>,
    )
}
