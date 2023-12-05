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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import java.util.*

object CryptoGenerator {

    fun randomRSASigningKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun randomECSigningKey(curve: Curve): ECKey = ECKeyGenerator(curve)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()
    fun rsaProofSigner(): DelegatingProofSigner {
        val keyPair = randomRSASigningKey(2048)
        val bindingKey = BindingKey.Jwk(
            jwk = keyPair.toPublicJWK(),
        )
        val proofSigner = DelegatingProofSigner(keyPair, JWSAlgorithm.RS256, bindingKey)
        return proofSigner
    }

    fun ecProofSigner(): DelegatingProofSigner {
        val keyPair = randomECSigningKey(Curve.P_256)
        val bindingKey = BindingKey.Jwk(
            jwk = keyPair.toPublicJWK(),
        )
        val proofSigner = DelegatingProofSigner(keyPair, JWSAlgorithm.ES256, bindingKey)
        return proofSigner
    }
}
