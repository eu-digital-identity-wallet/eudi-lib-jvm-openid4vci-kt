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

internal sealed interface CredentialType {
    data class MsoMdocDocType(val doctype: String, val claimSet: MsoMdocClaimSet?) : CredentialType

    data class SdJwtVcType(val type: String, val claims: GenericClaimSet?) : CredentialType

    data class W3CSignedJwtType(val type: List<String>, val claims: GenericClaimSet?) : CredentialType
}

/**
 * Credential(s) issuance request
 */
internal sealed interface CredentialIssuanceRequest {

    val encryption: IssuanceResponseEncryptionSpec?

    /**
     * Models an issuance request for a batch of credentials
     *
     * @param credentialRequests    List of individual credential issuance requests
     * @return A [CredentialIssuanceRequest]
     *
     */
    data class BatchRequest(
        val credentialRequests: List<SingleRequest>,
        override val encryption: IssuanceResponseEncryptionSpec?,
    ) : CredentialIssuanceRequest

    /**
     * Sealed hierarchy of credential issuance requests.
     */
    sealed interface SingleRequest : CredentialIssuanceRequest {
        val proof: Proof?
    }

    /**
     * Based on pre-agreed credential identifier.
     */
    data class IdentifierBased(
        val credentialId: CredentialIdentifier,
        override val proof: Proof?,
        override val encryption: IssuanceResponseEncryptionSpec?,
    ) : SingleRequest

    /**
     * Based on the format of the requested credential.
     */
    data class FormatBased(
        override val proof: Proof?,
        override val encryption: IssuanceResponseEncryptionSpec?,
        val credential: CredentialType,
    ) : SingleRequest

    companion object {
        internal fun formatBased(
            credentialConfiguration: CredentialConfiguration,
            claimSet: ClaimSet?,
            proof: Proof?,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): FormatBased {
            val cd = when (credentialConfiguration) {
                is MsoMdocCredential -> msoMdoc(credentialConfiguration, claimSet.ensureClaimSet())
                is SdJwtVcCredential -> sdJwtVc(credentialConfiguration, claimSet.ensureClaimSet())
                is W3CSignedJwtCredential -> w3cSignedJwt(credentialConfiguration, claimSet.ensureClaimSet())
                is W3CJsonLdSignedJwtCredential -> error("Format $FORMAT_W3C_JSONLD_SIGNED_JWT not supported")
                is W3CJsonLdDataIntegrityCredential -> error("Format $FORMAT_W3C_JSONLD_DATA_INTEGRITY not supported")
            }
            return FormatBased(proof, responseEncryptionSpec, cd)
        }
    }
}

private inline fun <reified C : ClaimSet> ClaimSet?.ensureClaimSet(): C? =
    if (this != null) {
        ensure(this is C) { InvalidIssuanceRequest("Invalid Claim Set provided for issuance") }
        this
    } else null

private fun msoMdoc(
    credentialConfiguration: MsoMdocCredential,
    claimSet: MsoMdocClaimSet?,
): CredentialType.MsoMdocDocType {
    fun MsoMdocClaimSet.validate() {
        if (isNotEmpty()) {
            val supportedClaims = credentialConfiguration.claims
            ensure(supportedClaims.isNotEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential [MsoMdoc-${credentialConfiguration.docType}]",
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
        doctype = credentialConfiguration.docType,
        claimSet = validClaimSet,
    )
}

private fun sdJwtVc(
    credentialConfiguration: SdJwtVcCredential,
    claimSet: GenericClaimSet?,
): CredentialType.SdJwtVcType {
    fun GenericClaimSet.validate() {
        if (claims.isNotEmpty()) {
            val supportedClaims = credentialConfiguration.claims
            ensure(!supportedClaims.isNullOrEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT_SD_JWT_VC-${credentialConfiguration.type}]",
                )
            }
            ensure(supportedClaims.keys.containsAll(claims)) {
                InvalidIssuanceRequest("Claim names requested are not supported by issuer")
            }
        }
    }

    val validClaimSet = claimSet?.apply { validate() }
    return CredentialType.SdJwtVcType(
        type = credentialConfiguration.type,
        claims = validClaimSet,
    )
}

private fun w3cSignedJwt(
    credentialConfiguration: W3CSignedJwtCredential,
    claimSet: GenericClaimSet?,
): CredentialType.W3CSignedJwtType {
    fun GenericClaimSet.validate() {
        if (claims.isNotEmpty()) {
            val supportedClaims = credentialConfiguration.credentialDefinition.credentialSubject
            ensure(!supportedClaims.isNullOrEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT_W3C_SIGNED_JWT-${credentialConfiguration.credentialDefinition.type}]",
                )
            }
            ensure(supportedClaims.keys.containsAll(claims)) {
                InvalidIssuanceRequest("Claim names requested are not supported by issuer")
            }
        }
    }

    val validClaimSet = claimSet?.apply { validate() }
    return CredentialType.W3CSignedJwtType(
        type = credentialConfiguration.credentialDefinition.type,
        claims = validClaimSet,
    )
}
