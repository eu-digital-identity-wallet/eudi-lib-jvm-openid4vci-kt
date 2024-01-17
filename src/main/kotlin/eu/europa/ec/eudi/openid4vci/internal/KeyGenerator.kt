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

import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.openid4vci.EcConfig
import eu.europa.ec.eudi.openid4vci.KeyGenerationConfig
import eu.europa.ec.eudi.openid4vci.RsaConfig
import java.util.*

object KeyGenerator {

    fun genKeyIfSupported(keyGenerationConfig: KeyGenerationConfig, alg: JWEAlgorithm): JWK? {
        return when (alg) {
            in JWEAlgorithm.Family.ECDH_ES ->
                keyGenerationConfig.ecConfig?.takeIf { alg in it.supportedJWEAlgorithms }?.let {
                    randomECEncryptionKey(it)
                }

            in JWEAlgorithm.Family.RSA ->
                keyGenerationConfig.rsaConfig?.takeIf { alg in it.supportedJWEAlgorithms }?.let {
                    randomRSAEncryptionKey(it)
                }

            else -> null
        }
    }

    fun randomRSAEncryptionKey(rsaConfig: RsaConfig): RSAKey = RSAKeyGenerator(rsaConfig.rcaKeySize)
        .keyUse(KeyUse.ENCRYPTION)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun randomECEncryptionKey(ecConfig: EcConfig): ECKey = ECKeyGenerator(ecConfig.ecKeyCurve)
        .keyUse(KeyUse.ENCRYPTION)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()
}
