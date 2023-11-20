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

import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.IssuanceResponseEncryptionSpec
import eu.europa.ec.eudi.openid4vci.Proof
import kotlinx.serialization.json.JsonObject

interface Format<M : CredentialMetadata.ByFormat, S : CredentialSupported, I : CredentialIssuanceRequest.SingleCredential> {

    fun matchSupportedAndToDomain(
        jsonObject: JsonObject,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialMetadata

    fun decodeCredentialSupportedFromJsonObject(
        jsonObject: JsonObject,
    ): CredentialSupportedTO

    fun supportedCredentialByFormat(
        metadata: M,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported

    fun constructIssuanceRequest(
        supportedCredential: S,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<CredentialIssuanceRequest.SingleCredential>

    fun mapRequestToTransferObject(credentialRequest: I): CredentialIssuanceRequestTO.SingleCredentialTO
}
