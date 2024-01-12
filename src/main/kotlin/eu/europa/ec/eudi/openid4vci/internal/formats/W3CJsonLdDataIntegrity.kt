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

import eu.europa.ec.eudi.openid4vci.ClaimSet
import eu.europa.ec.eudi.openid4vci.W3CJsonLdDataIntegrityCredential
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption

internal data object W3CJsonLdDataIntegrity :
    Format<
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
        W3CJsonLdDataIntegrityIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {

    override fun issuanceRequestToJson(
        request: W3CJsonLdDataIntegrityIssuanceRequest,
    ): CredentialIssuanceRequestTO.SingleCredentialTO {
        TODO("Not yet implemented")
    }
}
