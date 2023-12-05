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
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialSupported
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
     * Proof of possession is structured as a CWT
     *
     * @param cwt The proof CWT
     */
    @JvmInline
    value class Cwt(val cwt: String) : Proof
}

/**
 * Validate that the provided evidence is one of those that issuer supports
 */
internal fun createProof(
    issuerMetadata: CredentialIssuerMetadata,
    credentialSpec: CredentialSupported,
    cNonce: String,
    proofSigner: ProofSigner,
    proofType: ProofType,
): Proof = when (proofType) {
    ProofType.JWT -> {
        fun isAlgorithmSupported(): Boolean =
            credentialSpec.cryptographicSuitesSupported.contains(proofSigner.getAlgorithm().toString())

        fun isBindingMethodSupported(): Boolean =
            credentialSpec.cryptographicBindingMethodsSupported.contains(CryptographicBindingMethod.JWK)

        fun isProofTypeSupported(): Boolean =
            credentialSpec.proofTypesSupported.contains(ProofType.JWT)

        if (!isAlgorithmSupported()) {
            throw CredentialIssuanceError.ProofGenerationError.CryptographicSuiteNotSupported
        }
        if (!isBindingMethodSupported()) {
            throw CredentialIssuanceError.ProofGenerationError.CryptographicBindingMethodNotSupported
        }
        if (!isProofTypeSupported()) {
            throw CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
        }

        ProofBuilder.ofType(ProofType.JWT) {
            aud(issuerMetadata.credentialIssuerIdentifier.toString())

            when (val bindingKey = proofSigner.getBindingKey()) {
                is BindingKey.Jwk -> jwk(bindingKey.jwk)
                is BindingKey.Did -> TODO("DID proof evidence not supported yet")
                is BindingKey.X509 -> TODO("X509 proof evidence not supported yet")
            }

            nonce(cNonce)

            build(proofSigner)
        }
    }

    ProofType.CWT -> TODO("CWT Proofs are not yet supported")
}
