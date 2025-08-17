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

import com.nimbusds.jwt.JWT
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import kotlinx.serialization.Serializable

/**
 * Sealed hierarchy of the proofs of possession that can be included in a credential issuance request. Proofs are used
 * to bind the issued credential to the credential requester. They contain proof of possession of a bind key that can be
 * used to cryptographically verify that the presenter of the credential is also the holder of the credential.
 */
@Serializable(ProofSerializer::class)
internal sealed interface Proof {

    /**
     * Proof of possession is structured as signed JWT
     *
     * @param jwt The proof JWT
     */
    @JvmInline
    value class Jwt(val jwt: JWT) : Proof

    /**
     * Proof of possession is structured as a DI_VP
     *
     * @param diVp The proof DI_VP
     */
    @JvmInline
    value class DiVp(val diVp: String) : Proof

    /**
     * Proof of possession is structured as a Key Attestation JWT
     *
     * @param keyAttestation The proof Key Attestation JWT
     */
    @JvmInline
    value class Attestation(val keyAttestation: KeyAttestationJWT) : Proof
}
