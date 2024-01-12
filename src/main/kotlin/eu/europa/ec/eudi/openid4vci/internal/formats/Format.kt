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
import eu.europa.ec.eudi.openid4vci.CredentialSupported
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption

internal sealed interface Format<
    CS : CredentialSupported,
    in CL_SET : ClaimSet,
    IR : CredentialIssuanceRequest.SingleCredential,
    out IR_JSON,
    > {

    fun createIssuanceRequest(
        supportedCredential: CS,
        claimSet: CL_SET?,
        proof: Proof?,
        requestedCredentialResponseEncryption: RequestedCredentialResponseEncryption,
    ): Result<IR>

    val serializationSupport: FormatSerializationSupport<IR, IR_JSON>
}

internal interface FormatSerializationSupport<
    in IR : CredentialIssuanceRequest.SingleCredential,
    out IR_JSON,
    > {

    fun issuanceRequestToJson(request: IR): IR_JSON
}