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

import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIdentifier
import eu.europa.ec.eudi.openid4vci.IssuanceEncryptionSpecs

internal sealed interface CredentialConfigurationReference {
    data class ByCredentialId(val credentialIdentifier: CredentialIdentifier) : CredentialConfigurationReference
    data class ByCredentialConfigurationId(
        val credentialConfigurationId: CredentialConfigurationIdentifier,
    ) : CredentialConfigurationReference
}

/**
 * Credential(s) issuance request
 */
internal data class CredentialIssuanceRequest(
    val reference: CredentialConfigurationReference,
    val proofs: List<Proof>,
    val encryptionSpecs: IssuanceEncryptionSpecs,
) {

    companion object {
        internal fun byCredentialId(
            credentialIdentifier: CredentialIdentifier,
            proofs: List<Proof>,
            encryptionSpecs: IssuanceEncryptionSpecs,
        ): CredentialIssuanceRequest =
            CredentialIssuanceRequest(
                CredentialConfigurationReference.ByCredentialId(credentialIdentifier),
                proofs,
                encryptionSpecs,
            )

        internal fun byCredentialConfigurationId(
            credentialConfigurationId: CredentialConfigurationIdentifier,
            proofs: List<Proof>,
            encryptionSpecs: IssuanceEncryptionSpecs,
        ): CredentialIssuanceRequest =
            CredentialIssuanceRequest(
                CredentialConfigurationReference.ByCredentialConfigurationId(credentialConfigurationId),
                proofs,
                encryptionSpecs,
            )
    }
}
