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
import eu.europa.ec.eudi.openid4vci.formats.CredentialIssuanceRequest.SingleCredential
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject
import java.io.Serializable

internal object FormatRegistry {

    private val formats = mapOf(
        MsoMdoc.FORMAT to
            MsoMdoc() as Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential>,
        SdJwtVc.FORMAT to
            SdJwtVc() as Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential>,
        W3CSignedJwt.FORMAT to
            W3CSignedJwt() as Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential>,
        W3CJsonLdSignedJwt.FORMAT to
            W3CJsonLdSignedJwt() as Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential>,
        W3CJsonLdDataIntegrity.FORMAT to
            W3CJsonLdDataIntegrity() as Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential>,
    )

    fun byFormat(format: String): Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential> =
        formats[format] ?: throw IllegalArgumentException("Unsupported Credential format '$format'")

    fun byCredential(
        credentialMetadata: CredentialMetadata.ByFormat,
    ): Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential> =
        when (credentialMetadata) {
            is MsoMdoc.Model.CredentialMetadata -> formats[MsoMdoc.FORMAT]
            is SdJwtVc.Model.CredentialMetadata -> formats[SdJwtVc.FORMAT]
            is W3CSignedJwt.Model.CredentialMetadata -> formats[W3CSignedJwt.FORMAT]
            is W3CJsonLdSignedJwt.Model.CredentialMetadata -> formats[W3CJsonLdSignedJwt.FORMAT]
            is W3CJsonLdDataIntegrity.Model.CredentialMetadata -> formats[W3CJsonLdDataIntegrity.FORMAT]
        }
            ?: throw IllegalArgumentException("Unsupported Credential format")

    fun byCredentialSupported(
        credentialMetadata: CredentialSupported,
    ): Format<CredentialMetadata.ByFormat, CredentialSupported, SingleCredential> =
        when (credentialMetadata) {
            is MsoMdoc.Model.CredentialSupported -> formats[MsoMdoc.FORMAT]
            is SdJwtVc.Model.CredentialSupported -> formats[SdJwtVc.FORMAT]
            is W3CSignedJwt.Model.CredentialSupported -> formats[W3CSignedJwt.FORMAT]
            is W3CJsonLdSignedJwt.Model.CredentialSupported -> formats[W3CJsonLdSignedJwt.FORMAT]
            is W3CJsonLdDataIntegrity.Model.CredentialSupported -> formats[W3CJsonLdDataIntegrity.FORMAT]
        }
            ?: throw IllegalArgumentException("Unsupported Credential format")
}

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
