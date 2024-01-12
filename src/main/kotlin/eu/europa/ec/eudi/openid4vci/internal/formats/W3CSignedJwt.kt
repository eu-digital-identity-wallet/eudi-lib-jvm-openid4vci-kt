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
import eu.europa.ec.eudi.openid4vci.W3CSignedJwtCredential
import eu.europa.ec.eudi.openid4vci.internal.ClaimTO
import eu.europa.ec.eudi.openid4vci.internal.CredentialSupportedDisplayTO
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.*

internal data object W3CSignedJwt :
    Format<
        W3CSignedJwtCredentialTO,
        W3CSignedJwtCredential,
        ClaimSet,
        W3CSignedJwtIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {

    const val FORMAT = "jwt_vc_json"

    override fun createIssuanceRequest(
        supportedCredential: W3CSignedJwtCredential,
        claimSet: ClaimSet?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    ): Result<W3CSignedJwtIssuanceRequest> = TODO("Not yet implemented")

    override val serializationSupport:
        FormatSerializationSupport<
            W3CSignedJwtCredentialTO,
            W3CSignedJwtCredential,
            W3CSignedJwtIssuanceRequest,
            CredentialIssuanceRequestTO.SingleCredentialTO,
            >
        get() = W3CSignedJwtSerializationSupport
}

internal class W3CSignedJwtIssuanceRequest(
    override val format: String,
    override val proof: Proof?,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
) : CredentialIssuanceRequest.SingleCredential {

    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        W3CSignedJwt.serializationSupport.issuanceRequestToJson(this)
}

//
// Serialization
//

private object W3CSignedJwtSerializationSupport :
    FormatSerializationSupport<
        W3CSignedJwtCredentialTO,
        W3CSignedJwtCredential,
        W3CSignedJwtIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {
    override fun credentialSupportedFromJson(csJson: W3CSignedJwtCredentialTO): W3CSignedJwtCredential {
        val bindingMethods =
            csJson.cryptographicBindingMethodsSupported?.toCryptographicBindingMethods()
                ?: emptyList()
        val display = csJson.display?.map { it.toDomain() } ?: emptyList()
        val proofTypesSupported = csJson.proofTypesSupported.toProofTypes()
        val cryptographicSuitesSupported = csJson.cryptographicSuitesSupported ?: emptyList()

        return W3CSignedJwtCredential(
            csJson.scope,
            bindingMethods,
            cryptographicSuitesSupported,
            proofTypesSupported,
            display,
            csJson.credentialDefinition.toDomain(),
            csJson.order ?: emptyList(),
        )
    }

    private fun W3CSignedJwtCredentialTO.CredentialDefinitionTO.toDomain(): W3CSignedJwtCredential.CredentialDefinition =
        W3CSignedJwtCredential.CredentialDefinition(
            type = types,
            credentialSubject = credentialSubject?.mapValues { nameAndClaim ->
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

    override fun issuanceRequestToJson(request: W3CSignedJwtIssuanceRequest): CredentialIssuanceRequestTO.SingleCredentialTO {
        TODO("Not yet implemented")
    }
}

/**
 * The data of a W3C Verifiable Credential issued as a signed JWT, not using JSON-LD.
 */
@Serializable
@SerialName(W3CSignedJwt.FORMAT)
internal data class W3CSignedJwtCredentialTO(
    @SerialName("format") @Required override val format: String = W3CSignedJwt.FORMAT,
    @SerialName("scope") override val scope: String? = null,
    @SerialName("cryptographic_binding_methods_supported")
    override val cryptographicBindingMethodsSupported: List<String>? = null,
    @SerialName("cryptographic_suites_supported")
    override val cryptographicSuitesSupported: List<String>? = null,
    @SerialName("proof_types_supported")
    override val proofTypesSupported: List<String>? = null,
    @SerialName("display") override val display: List<CredentialSupportedDisplayTO>? = null,
    @SerialName("credential_definition") @Required val credentialDefinition: CredentialDefinitionTO,
    @SerialName("order") val order: List<String>? = null,
) : CredentialSupportedTO {
    init {
        require(format == W3CSignedJwt.FORMAT) { "invalid format '$format'" }
    }

    @Serializable
    data class CredentialDefinitionTO(
        @SerialName("type") val types: List<String>,
        @SerialName("credentialSubject") val credentialSubject: Map<String, ClaimTO>? = null,
    )

    override fun toDomain(): CredentialSupported = W3CSignedJwt.serializationSupport.credentialSupportedFromJson(this)
}
