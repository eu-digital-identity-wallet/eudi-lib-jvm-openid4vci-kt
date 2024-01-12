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

import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.RequestedCredentialResponseEncryption
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.JsonObject

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

        @Deprecated("Don't use it")
        fun toTransferObject(): CredentialIssuanceRequestTO.SingleCredentialTO
    }
}

@kotlinx.serialization.Serializable
@OptIn(ExperimentalSerializationApi::class)
@JsonClassDiscriminator("format")
internal sealed interface CredentialIssuanceRequestTO {

    @kotlinx.serialization.Serializable
    @SerialName("batch-credential-request")
    data class BatchCredentialsTO(
        @SerialName("credential_requests") val credentialRequests: List<SingleCredentialTO>,
    ) : CredentialIssuanceRequestTO

    @kotlinx.serialization.Serializable
    sealed interface SingleCredentialTO : CredentialIssuanceRequestTO {
        val proof: Proof?
        val credentialEncryptionJwk: JsonObject?
        val credentialResponseEncryptionAlg: String?
        val credentialResponseEncryptionMethod: String?
    }
}
