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
package eu.europa.ec.eudi.openid4vci.internal.formats

import eu.europa.ec.eudi.openid4vci.Claim
import eu.europa.ec.eudi.openid4vci.ClaimSet
import eu.europa.ec.eudi.openid4vci.CredentialSupported
import eu.europa.ec.eudi.openid4vci.W3CJsonLdDataIntegrityCredential
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import eu.europa.ec.eudi.openid4vci.internal.formats.W3CJsonLdDataIntegrityCredentialTO.CredentialDefinitionTO
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.net.URL
import java.util.*

internal data object W3CJsonLdDataIntegrity :
    Format<
        W3CJsonLdDataIntegrityCredentialTO,
        W3CJsonLdDataIntegrityCredential,
        ClaimSet,
        W3CJsonLdDataIntegrityIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {

    const val FORMAT = "ldp_vc"

    override fun createIssuanceRequest(
        supportedCredential: W3CJsonLdDataIntegrityCredential,
        claimSet: ClaimSet?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    ): Result<W3CJsonLdDataIntegrityIssuanceRequest> = TODO("Not yet implemented")

    override val serializationSupport:
        FormatSerializationSupport<
            W3CJsonLdDataIntegrityCredentialTO,
            W3CJsonLdDataIntegrityCredential,
            W3CJsonLdDataIntegrityIssuanceRequest,
            CredentialIssuanceRequestTO.SingleCredentialTO,
            >
        get() = W3CJsonLdDataIntegritySerializationSupport
}

internal class W3CJsonLdDataIntegrityIssuanceRequest(
    override val format: String,
    override val proof: Proof?,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
) : CredentialIssuanceRequest.SingleCredential {
    @Deprecated("Don't use it")
    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        W3CJsonLdDataIntegritySerializationSupport.issuanceRequestToJson(this)
}

//
// Serialization
//

private object W3CJsonLdDataIntegritySerializationSupport :
    FormatSerializationSupport<
        W3CJsonLdDataIntegrityCredentialTO,
        W3CJsonLdDataIntegrityCredential,
        W3CJsonLdDataIntegrityIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {
    override fun credentialSupportedFromJson(
        csJson: W3CJsonLdDataIntegrityCredentialTO,
    ): W3CJsonLdDataIntegrityCredential {
        val bindingMethods =
            csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
                ?: emptyList()
        val display = csJson.display?.map { it.toDomain() } ?: emptyList()
        val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

        return W3CJsonLdDataIntegrityCredential(
            csJson.scope, bindingMethods, cryptographicSuitesSupported, proofTypesSupported,
            display, csJson.context, csJson.type, toDomain(csJson.credentialDefinition),
            csJson.order ?: emptyList(),
        )
    }

    private fun toDomain(credentialDefinitionTO: CredentialDefinitionTO): W3CJsonLdDataIntegrityCredential.CredentialDefinition =
        W3CJsonLdDataIntegrityCredential.CredentialDefinition(
            context = credentialDefinitionTO.context.map { URL(it) },
            type = credentialDefinitionTO.types,
            credentialSubject = credentialDefinitionTO.credentialSubject?.mapValues { nameAndClaim ->
                nameAndClaim.value.let {
                    Claim(
                        it.mandatory ?: false,
                        it.valueType,
                        it.display?.map { displayObject ->
                            Claim.Display(
                                displayObject.name,
                                displayObject.locale?.let { languageTag -> Locale.forLanguageTag(languageTag) },
                            )
                        } ?: emptyList(),
                    )
                }
            },
        )

    override fun issuanceRequestToJson(
        request: W3CJsonLdDataIntegrityIssuanceRequest,
    ): CredentialIssuanceRequestTO.SingleCredentialTO {
        TODO("Not yet implemented")
    }
}

/**
 * The data of a W3C Verifiable Credential issued as using Data Integrity and JSON-LD.
 */
@Serializable
@SerialName(W3CJsonLdDataIntegrity.FORMAT)
internal data class W3CJsonLdDataIntegrityCredentialTO(
    @SerialName("format") @Required override val format: String = W3CJsonLdDataIntegrity.FORMAT,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("@context") @Required val context: List<String> = emptyList(),
    @SerialName("type") @Required val type: List<String> = emptyList(),
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
) : CredentialSupportedTO {
    init {
        require(format == W3CJsonLdDataIntegrity.FORMAT) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("@context") val context: List<String>,
        @SerialName("type") val types: List<String>,
        @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
    )

    override fun toDomain(): CredentialSupported =
        W3CJsonLdDataIntegritySerializationSupport.credentialSupportedFromJson(this)
}
