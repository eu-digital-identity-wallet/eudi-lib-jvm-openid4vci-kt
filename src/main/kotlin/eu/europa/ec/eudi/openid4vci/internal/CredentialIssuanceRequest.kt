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
package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.InvalidIssuanceRequest

internal sealed interface CredentialType {
    data class MsoMdocDocType(val doctype: String, val claimSet: MsoMdocClaimSet?) : CredentialType

    data class SdJwtVcType(val type: String, val claims: GenericClaimSet?) : CredentialType

    data class W3CSignedJwtType(val type: List<String>, val claims: GenericClaimSet?) : CredentialType
}

internal sealed interface CredentialConfigurationReference {
    data class ById(val credentialIdentifier: CredentialIdentifier) : CredentialConfigurationReference
    data class ByFormat(val credential: CredentialType) : CredentialConfigurationReference
}

/**
 * Credential(s) issuance request
 */
internal data class CredentialIssuanceRequest(
    val reference: CredentialConfigurationReference,
    val proofs: List<Proof>,
    val encryption: IssuanceResponseEncryptionSpec?,
) {

    companion object {
        internal fun byId(
            credentialIdentifier: CredentialIdentifier,
            proofs: List<Proof>,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): CredentialIssuanceRequest =
            CredentialIssuanceRequest(
                CredentialConfigurationReference.ById(credentialIdentifier),
                proofs,
                responseEncryptionSpec,
            )

        internal fun formatBased(
            credentialConfiguration: CredentialConfiguration,
            claimSet: ClaimSet?,
            proofs: List<Proof>,
            responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
        ): CredentialIssuanceRequest {
            val cd = when (credentialConfiguration) {
                is MsoMdocCredential -> msoMdoc(credentialConfiguration, claimSet.ensureClaimSet())
                is SdJwtVcCredential -> sdJwtVc(credentialConfiguration, claimSet.ensureClaimSet())
                is W3CSignedJwtCredential -> w3cSignedJwt(credentialConfiguration, claimSet.ensureClaimSet())
                is W3CJsonLdSignedJwtCredential -> error("Format $FORMAT_W3C_JSONLD_SIGNED_JWT not supported")
                is W3CJsonLdDataIntegrityCredential -> error("Format $FORMAT_W3C_JSONLD_DATA_INTEGRITY not supported")
            }

            return CredentialIssuanceRequest(
                CredentialConfigurationReference.ByFormat(cd),
                proofs,
                responseEncryptionSpec,
            )
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

            // TODO [d15]: Remove when requests are adapted to d15
//            forEach { (nameSpace, claimName) ->
//                val supportedClaimNames = supportedClaims[nameSpace]
//                ensureNotNull(supportedClaimNames) {
//                    InvalidIssuanceRequest("Namespace $nameSpace not supported by issuer")
//                }
//                ensure(claimName in supportedClaimNames) {
//                    InvalidIssuanceRequest("Requested claim name $claimName is not supported by issuer")
//                }
//            }
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
            ensure(supportedClaims.isNotEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT_SD_JWT_VC-${credentialConfiguration.type}]",
                )
            }
            // TODO [d15]: Remove when requests are adapted to d15
//            ensure(supportedClaims.keys.containsAll(claims)) {
//                InvalidIssuanceRequest("Claim names requested are not supported by issuer")
//            }
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
            val supportedClaims = credentialConfiguration.claims
            ensure(supportedClaims.isNotEmpty()) {
                InvalidIssuanceRequest(
                    "Issuer does not support claims for credential " +
                        "[$FORMAT_W3C_SIGNED_JWT-${credentialConfiguration.credentialDefinition.type}]",
                )
            }
            // TODO [d15]: Remove when requests are adapted to d15
//            ensure(supportedClaims.keys.containsAll(claims)) {
//                InvalidIssuanceRequest("Claim names requested are not supported by issuer")
//            }
        }
    }

    val validClaimSet = claimSet?.apply { validate() }
    return CredentialType.W3CSignedJwtType(
        type = credentialConfiguration.credentialDefinition.type,
        claims = validClaimSet,
    )
}
