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
import eu.europa.ec.eudi.openid4vci.W3CJsonLdSignedJwtCredential
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import java.util.*

internal data object W3CJsonLdSignedJwt :
    Format<
        W3CJsonLdSignedJwtCredential,
        ClaimSet,
        W3CJsonLdSignedJwtIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {

    const val FORMAT = "jwt_vc_json-ld"

    override fun createIssuanceRequest(
        supportedCredential: W3CJsonLdSignedJwtCredential,
        claimSet: ClaimSet?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    ): Result<W3CJsonLdSignedJwtIssuanceRequest> = TODO("W3CJsonLdSignedJwt Not yet implemented")

    override val serializationSupport:
        FormatSerializationSupport<W3CJsonLdSignedJwtIssuanceRequest, CredentialIssuanceRequestTO.SingleCredentialTO>
        get() = W3CJsonLdSignedJwtSerializationSupport
}

internal class W3CJsonLdSignedJwtIssuanceRequest(
    override val format: String,
    override val proof: Proof?,
    override val requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
) : CredentialIssuanceRequest.SingleCredential {
    override fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO =
        W3CJsonLdSignedJwt.serializationSupport.issuanceRequestToJson(this)
}

//
// Serialization
//

private object W3CJsonLdSignedJwtSerializationSupport :
    FormatSerializationSupport<
        W3CJsonLdSignedJwtIssuanceRequest,
        CredentialIssuanceRequestTO.SingleCredentialTO,
        > {

    override fun issuanceRequestToJson(request: W3CJsonLdSignedJwtIssuanceRequest): CredentialIssuanceRequestTO.SingleCredentialTO {
        TODO("Not yet implemented")
    }
}
