/*
 * Copyright (c) 2023-2026 European Commission
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
package eu.europa.ec.eudi.openid4vci.internal.http

import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation

internal class GetAbcaChallengeAndDPoPNonce(
    private val provisionClientAttestation: suspend () -> ProvisionClientAttestation.Provisioned?,
    private val challengeEndpointClient: ChallengeEndpointClient?,
) {
    suspend operator fun invoke(existingAbcaChallenge: Nonce?, existingDpopNonce: Nonce?): Pair<Nonce?, Nonce?> {
        val provisionedClientAttestation = provisionClientAttestation()
        if (null == provisionedClientAttestation) {
            return null to existingDpopNonce
        }

        if (null != existingAbcaChallenge) {
            return existingAbcaChallenge to existingDpopNonce
        }

        if (null == challengeEndpointClient) {
            return null to existingDpopNonce
        }

        val (newAbcaChallenge, newDPoPNonce) = challengeEndpointClient.getChallenge().getOrThrow()
        return newAbcaChallenge to (newDPoPNonce ?: existingDpopNonce)
    }
}
