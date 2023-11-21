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
package eu.europa.ec.eudi.openid4vci.formats

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject
import java.io.Serializable
import java.util.*

@kotlinx.serialization.Serializable
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("format")
sealed interface CredentialIssuanceRequestTO {

    @kotlinx.serialization.Serializable
    @SerialName("batch-credential-request")
    data class BatchCredentialsTO(
        @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
    ) : CredentialIssuanceRequestTO

    @kotlinx.serialization.Serializable
    sealed interface SingleCredentialTO : CredentialIssuanceRequestTO {
        val proof: JsonObject?
        val credentialEncryptionJwk: JsonObject?
        val credentialResponseEncryptionAlg: String?
        val credentialResponseEncryptionMethod: String?
    }
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
 * Credentials supported by an Issuer.
 */
sealed interface CredentialSupported : Serializable {

    val scope: String?
    val cryptographicBindingMethodsSupported: List<CryptographicBindingMethod>
    val cryptographicSuitesSupported: List<String>
    val proofTypesSupported: List<ProofType>
    val display: List<Display>
}

/**
 * A Credential being offered in a Credential Offer.
 */
sealed interface CredentialMetadata : Serializable {

    data class ByScope(val scope: Scope) : CredentialMetadata

    sealed interface ByFormat : CredentialMetadata
}

/**
 * Sealed interface to model the set of specific claims that need to be included in the issued credential.
 * This set of claims is modelled differently depending on the credential format.
 */
sealed interface ClaimSet

/**
 * Credential(s) issuance request
 */
sealed interface CredentialIssuanceRequest {

    /**
     * Models an issuance request for a batch of credentials
     *
     * @param credentialRequests    List of individual credential issuance requests
     * @return A [CredentialIssuanceRequest]
     *
     */
    data class BatchCredentials(
        val credentialRequests: List<SingleCredential>,
    ) : CredentialIssuanceRequest

    /**
     * Sealed hierarchy of credential issuance requests based on the format of the requested credential.
     */
    sealed interface SingleCredential : CredentialIssuanceRequest {
        val format: String
        val proof: Proof?
        val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption

        fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO

        companion object {

            /**
             * Utility method to create the [RequestedCredentialResponseEncryption] attribute of the issuance request.
             * Construction logic is independent of the credential's format.
             *
             * @param credentialEncryptionJwk   Key pair in JWK format used for issuance response encryption/decryption
             * @param credentialResponseEncryptionAlg   Encryption algorithm to be used
             * @param credentialResponseEncryptionMethod Encryption method to be used
             */
            fun requestedCredentialResponseEncryption(
                credentialEncryptionJwk: JWK?,
                credentialResponseEncryptionAlg: JWEAlgorithm?,
                credentialResponseEncryptionMethod: EncryptionMethod?,
            ): RequestedCredentialResponseEncryption =
                if (credentialEncryptionJwk == null &&
                    credentialResponseEncryptionAlg == null &&
                    credentialResponseEncryptionMethod == null
                ) {
                    RequestedCredentialResponseEncryption.NotRequested
                } else {
                    var encryptionMethod = credentialResponseEncryptionMethod
                    when {
                        credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null ->
                            encryptionMethod = EncryptionMethod.A256GCM

                        credentialResponseEncryptionAlg != null && credentialEncryptionJwk == null ->
                            throw CredentialIssuanceError.InvalidIssuanceRequest("Encryption algorithm was provided but no encryption key")

                        credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null ->
                            throw CredentialIssuanceError.InvalidIssuanceRequest(
                                "Credential response encryption algorithm must be specified if Credential " +
                                    "response encryption method is provided",
                            )
                    }
                    RequestedCredentialResponseEncryption.Requested(
                        encryptionJwk = credentialEncryptionJwk!!,
                        responseEncryptionAlg = credentialResponseEncryptionAlg!!,
                        responseEncryptionMethod = encryptionMethod!!,
                    )
                }
        }
    }
}

/**
 * Utility method to convert a [DisplayTO] transfer object to the respective [Display] domain object.
 */
fun DisplayTO.toDomain(): Display {
    fun DisplayTO.LogoObject.toLogo(): Display.Logo =
        Display.Logo(
            url?.let { HttpsUrl(it).getOrThrow() },
            alternativeText,
        )

    return Display(
        name,
        locale?.let { Locale.forLanguageTag(it) },
        logo?.toLogo(),
        description,
        backgroundColor,
        textColor,
    )
}

/**
 * Utility method to convert a list of string to a list of [CryptographicBindingMethod].
 */
fun List<String>.toCryptographicBindingMethods(): List<CryptographicBindingMethod> =
    map {
        when (it) {
            "jwk" -> CryptographicBindingMethod.JWK
            "cose_key" -> CryptographicBindingMethod.COSE
            "mso" -> CryptographicBindingMethod.MSO
            else ->
                if (it.startsWith("did")) {
                    CryptographicBindingMethod.DID(it)
                } else {
                    throw IllegalArgumentException("Unknown Cryptographic Binding Method '$it'")
                }
        }
    }

/**
 * Utility method to convert a list of string to a list of [ProofType].
 */
fun List<String>?.toProofTypes(): List<ProofType> =
    this?.map {
        when (it) {
            "jwt" -> ProofType.JWT
            "cwt" -> ProofType.CWT
            else -> throw IllegalArgumentException("Unknown Proof Type '$it'")
        }
    } ?: emptyList<ProofType>()
        .ifEmpty {
            listOf(ProofType.JWT)
        }
