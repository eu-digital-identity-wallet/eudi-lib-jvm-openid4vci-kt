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
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL

class DelegatingProofSigner private constructor(
    private val delegate: JWSSigner,
    private val bindingKey: BindingKey,
    private val algorithm: JWSAlgorithm,
) : ProofSigner {
    override fun getBindingKey(): BindingKey = this.bindingKey

    override fun getAlgorithm(): JWSAlgorithm = this.algorithm

    override fun getJCAContext(): JCAContext = this.delegate.jcaContext

    override fun supportedJWSAlgorithms(): MutableSet<JWSAlgorithm> = mutableSetOf(algorithm)

    override fun sign(header: JWSHeader?, signingInput: ByteArray?): Base64URL = delegate.sign(header, signingInput)

    companion object {
        operator fun invoke(
            jwk: JWK,
            alg: JWSAlgorithm,
            bindingKey: BindingKey,
        ): DelegatingProofSigner {
            val signer = DefaultJWSSignerFactory().createJWSSigner(jwk, alg)
            return DelegatingProofSigner(signer, bindingKey, alg)
        }
    }
}
