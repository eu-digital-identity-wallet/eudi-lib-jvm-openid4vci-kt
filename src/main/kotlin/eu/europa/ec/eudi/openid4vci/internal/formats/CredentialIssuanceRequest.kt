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

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidIssuanceRequest
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.ensure
import eu.europa.ec.eudi.openid4vci.internal.ensureNotNull

internal const val FORMAT_MSO_MDOC = "mso_mdoc"
internal const val FORMAT_SD_JWT_VC = "vc+sd-jwt"
internal const val FORMAT_W3C_JSONLD_DATA_INTEGRITY = "ldp_vc"
internal const val FORMAT_W3C_JSONLD_SIGNED_JWT = "jwt_vc_json-ld"
internal const val FORMAT_W3C_SIGNED_JWT = "jwt_vc_json"

internal sealed interface CredentialType {
    data class MsoMdocDocType(val doctype: String, val claimSet: MsoMdocClaimSet?) : CredentialType

    data class SdJwtVcType(val type: String, val claims: GenericClaimSet?) : CredentialType
}

/**
 * Credential(s) issuance request
 */
internal sealed interface CredentialIssuanceRequest {

    /**
     * Models an issuance request for a batch of credentials
     *
     * @param credentialRequests    List of individual credential issuance requests
     * @return A [CredentialIssuanceRequest]
     *
     */
    data class BatchRequest(
        val credentialRequests: List<SingleRequest>,
    ) : CredentialIssuanceRequest

    /**
     * Sealed hierarchy of credential issuance requests based on the format of the requested credential.
     */
    data class SingleRequest(
        val proof: Proof?,
        val encryption: IssuanceResponseEncryptionSpec?,
        val credential: CredentialType,
    ) : CredentialIssuanceRequest

    companion object {
        internal fun singleRequest(
            supportedCredential: CredentialSupported,
            claimSet: ClaimSet?,
            proof: Proof?,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): SingleRequest {
            val cd = when (supportedCredential) {
                is MsoMdocCredential -> msoMdoc(supportedCredential, claimSet.ensureClaimSet())
                is SdJwtVcCredential -> sdJwtVc(supportedCredential, claimSet.ensureClaimSet())
                is W3CSignedJwtCredential -> error("Format $FORMAT_W3C_SIGNED_JWT not supported")
                is W3CJsonLdSignedJwtCredential -> error("Format $FORMAT_W3C_JSONLD_SIGNED_JWT not supported")
                is W3CJsonLdDataIntegrityCredential -> error("Format $FORMAT_W3C_JSONLD_DATA_INTEGRITY not supported")
            }
            return SingleRequest(proof, responseEncryptionSpec, cd)
        }
    }
}

private inline fun <reified C : ClaimSet> ClaimSet?.ensureClaimSet(): C? =
    if (this != null) {
        ensure(this is C) { InvalidIssuanceRequest("Invalid Claim Set provided for issuance") }
        this
    } else null

private fun msoMdoc(supportedCredential: MsoMdocCredential, claimSet: MsoMdocClaimSet?): CredentialType.MsoMdocDocType {
    fun MsoMdocClaimSet.validate() {
        if (isNotEmpty()) {
            val supportedClaims = supportedCredential.claims
            ensure(supportedClaims.isNotEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${supportedCredential.docType}]",
                )
            }

            forEach { (nameSpace, claimName) ->
                val supportedClaimNames = supportedClaims[nameSpace]
                ensureNotNull(supportedClaimNames) {
                    InvalidIssuanceRequest("Namespace $nameSpace not supported by issuer")
                }
                ensure(claimName in supportedClaimNames) {
                    InvalidIssuanceRequest("Requested claim name $claimName is not supported by issuer")
                }
            }
        }
    }

    val validClaimSet = claimSet?.apply { validate() }
    return CredentialType.MsoMdocDocType(
        doctype = supportedCredential.docType,
        claimSet = validClaimSet,
    )
}

private fun sdJwtVc(
    supportedCredential: SdJwtVcCredential,
    claimSet: GenericClaimSet?,
): CredentialType.SdJwtVcType {
    fun GenericClaimSet.validate() {
        if (claims.isNotEmpty()) {
            val supportedClaims = supportedCredential.credentialDefinition.claims
            ensure(!supportedClaims.isNullOrEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT_SD_JWT_VC-${supportedCredential.credentialDefinition.type}]",
                )
            }
            ensure(supportedClaims.keys.containsAll(claims)) {
                InvalidIssuanceRequest("Claim names requested are not supported by issuer")
            }
        }
    }

    val validClaimSet = claimSet?.apply { validate() }
    return CredentialType.SdJwtVcType(
        type = supportedCredential.credentialDefinition.type,
        claims = validClaimSet,
    )
}
