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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.JWK

class DelegatingProofSigner private constructor(
    private val delegate: JWSSigner,
    private val bindingKey: BindingKey,
    private val algorithm: JWSAlgorithm,
) : JWSSigner by delegate, ProofSigner {

    override fun getBindingKey(): BindingKey = this.bindingKey

    override fun getAlgorithm(): JWSAlgorithm = this.algorithm

    companion object {
        operator fun invoke(
            privateKey: JWK,
            alg: JWSAlgorithm,
            publicKey: BindingKey,
        ): DelegatingProofSigner {
            val signer = DefaultJWSSignerFactory().createJWSSigner(privateKey, alg)
            return DelegatingProofSigner(signer, publicKey, alg)
        }
    }
}
