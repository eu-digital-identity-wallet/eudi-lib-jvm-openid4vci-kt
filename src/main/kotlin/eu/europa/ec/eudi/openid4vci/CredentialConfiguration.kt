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
}

/**
 * Proof types supported by a Credential Issuer.
 */
enum class ProofType : Serializable {
    JWT,
    LDP_VP,
}

sealed interface ProofTypeMeta : Serializable {
    data class Jwt(val algorithms: List<JWSAlgorithm>) : ProofTypeMeta {
        init {
            require(algorithms.isNotEmpty()) { "Supported algorithms in case of JWT cannot be empty" }
        }
    }

    data object LdpVp : ProofTypeMeta {
        private fun readResolve(): Any = LdpVp
    }

    data class Unsupported(val type: String) : ProofTypeMeta
}

fun ProofTypeMeta.type(): ProofType? = when (this) {
    is ProofTypeMeta.Jwt -> ProofType.JWT
    is ProofTypeMeta.LdpVp -> ProofType.LDP_VP
    is ProofTypeMeta.Unsupported -> null
}

@JvmInline
value class ProofTypesSupported private constructor(val values: Set<ProofTypeMeta>) {

    operator fun get(type: ProofType): ProofTypeMeta? = values.firstOrNull { it.type() == type }

    companion object {
        val Empty: ProofTypesSupported = ProofTypesSupported(emptySet())
        operator fun invoke(values: Set<ProofTypeMeta>): ProofTypesSupported {
            require(values.groupBy(ProofTypeMeta::type).all { (_, instances) -> instances.size == 1 }) {
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

/**
 * Credentials supported by an Issuer.
 */
sealed interface CredentialConfiguration : Serializable {
    val scope: String?
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val credentialSigningAlgorithmsSupported: List<String>
    val proofTypesSupported: ProofTypesSupported
    val display: List<Display>
}

/**
 * The details of a Claim.
 */
@kotlinx.serialization.Serializable
data class Claim(
    @SerialName("mandatory") val mandatory: Boolean? = false,
    @SerialName("value_type") val valueType: String? = null,
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
typealias Namespace = String
typealias ClaimName = String
typealias MsoMdocClaims = Map<Namespace, Map<ClaimName, Claim>>

fun MsoMdocClaims.toClaimSet(): MsoMdocClaimSet = MsoMdocClaimSet(
    mapValues { (_, claims) -> claims.keys.toList() }
        .flatMap { (nameSpace, claims) -> claims.map { claimName -> nameSpace to claimName } },
)

data class MsoMdocPolicy(val oneTimeUse: Boolean, val batchSize: Int?) : Serializable

/**
 * The data of a Verifiable Credentials issued as an ISO MDOC.
 */
data class MsoMdocCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val credentialSigningAlgorithmsSupported: List<String> = emptyList(),
    val isoCredentialSigningAlgorithmsSupported: List<CoseAlgorithm> = emptyList(),
    val isoCredentialCurvesSupported: List<CoseCurve> = emptyList(),
    val isoPolicy: MsoMdocPolicy?,
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val display: List<Display> = emptyList(),
    val docType: String,
    val claims: MsoMdocClaims = emptyMap(),
    val order: List<ClaimName> = emptyList(),
) : CredentialConfiguration

data class SdJwtVcCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val credentialSigningAlgorithmsSupported: List<String> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val display: List<Display> = emptyList(),
    val type: String,
    val claims: Map<ClaimName, Claim?>?,
    val order: List<ClaimName> = emptyList(),
) : CredentialConfiguration

data class W3CJsonLdCredentialDefinition(
    val context: List<URL>,
    val type: List<String>,
    val credentialSubject: Map<ClaimName, Claim?>?,
)

/**
 * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
 */
data class W3CJsonLdDataIntegrityCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val credentialSigningAlgorithmsSupported: List<String> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val display: List<Display> = emptyList(),
    val context: List<String> = emptyList(),
    val type: List<String> = emptyList(),
    val credentialDefinition: W3CJsonLdCredentialDefinition,
    val order: List<ClaimName> = emptyList(),
) : CredentialConfiguration

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT using JSON-LD.
 */
data class W3CJsonLdSignedJwtCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val credentialSigningAlgorithmsSupported: List<String> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val display: List<Display> = emptyList(),
    val context: List<String> = emptyList(),
    val credentialDefinition: W3CJsonLdCredentialDefinition,
    val order: List<ClaimName> = emptyList(),
) : CredentialConfiguration

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
data class W3CSignedJwtCredential(
    override val scope: String? = null,
    override val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod> = emptyList(),
    override val credentialSigningAlgorithmsSupported: List<String> = emptyList(),
    override val proofTypesSupported: ProofTypesSupported = ProofTypesSupported.Empty,
    override val display: List<Display> = emptyList(),
    val credentialDefinition: CredentialDefinition,
    val order: List<ClaimName> = emptyList(),
) : CredentialConfiguration {

    data class CredentialDefinition(
        val type: List<String>,
        val credentialSubject: Map<ClaimName, Claim?>?,
    )
}
