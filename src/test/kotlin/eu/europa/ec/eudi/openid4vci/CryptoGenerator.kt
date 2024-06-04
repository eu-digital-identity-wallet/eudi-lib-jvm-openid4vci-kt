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
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.time.Clock
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

    fun rsaProofSigner(signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): PopSigner.Jwt {
        val keyPair = randomRSASigningKey(2048)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return PopSigner.jwtPopSigner(keyPair, signingAlgorithm, bindingKey)
    }

    fun ecProofSigner(curve: Curve = Curve.P_256, alg: JWSAlgorithm = JWSAlgorithm.ES256): PopSigner.Jwt {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return PopSigner.jwtPopSigner(keyPair, alg, bindingKey)
    }

    private fun ecCwtPopSigner(
        clock: Clock,
        alg: CoseAlgorithm,
        curve: CoseCurve,
        kid: String,
    ): PopSigner.Cwt {
        val keyPair: ECKey = ECKeyGenerator(checkNotNull(curve.toNimbus()))
            .keyUse(KeyUse.SIGNATURE)
            .keyID(kid)
            .algorithm(checkNotNull(alg.toNimbus()))
            .issueTime(Date.from(clock.instant()))
            .generate()

        val bindingKey = CwtBindingKey.CoseKey(keyPair.toPublicJWK())
        return PopSigner.Cwt(
            algorithm = alg,
            curve = curve,
            bindingKey = bindingKey,
            sign = signer(keyPair.toECPrivateKey()),
        )
    }

    private fun signer(key: ECPrivateKey): suspend (ByteArray) -> ByteArray = { data ->

        val sig = Signature.getInstance("SHA256withECDSAinP1363Format").apply {
            initSign(key)
            update(data)
        }
        sig.sign()
    }

    fun popSigner(
        clock: Clock = Clock.systemDefaultZone(),
        proofTypeMeta: ProofTypeMeta,
        kid: String = UUID.randomUUID().toString(),
    ): PopSigner? =
        when (proofTypeMeta) {
            is ProofTypeMeta.Cwt -> {
                val supported: List<Pair<CoseAlgorithm, CoseCurve>> = proofTypeMeta.algorithms.zip(proofTypeMeta.curves)
                sequenceOf(
                    CoseAlgorithm.ES256 to CoseCurve.P_256,
                    CoseAlgorithm.ES384 to CoseCurve.P_384,
                    CoseAlgorithm.ES512 to CoseCurve.P_521,
                ).firstOrNull { it in supported }?.let { (a, c) ->
                    ecCwtPopSigner(clock = clock, alg = a, curve = c, kid = kid)
                }
            }

            is ProofTypeMeta.Jwt -> {
                proofTypeMeta.algorithms.asSequence().mapNotNull { alg ->
                    when (alg) {
                        JWSAlgorithm.ES256 -> ecProofSigner(Curve.P_256, alg)
                        JWSAlgorithm.ES384 -> ecProofSigner(Curve.P_384, alg)
                        JWSAlgorithm.ES512 -> ecProofSigner(Curve.P_521, alg)
                        in JWSAlgorithm.Family.RSA -> rsaProofSigner(alg)
                        else -> null
                    }
                }.firstOrNull()
            }
            ProofTypeMeta.LdpVp -> null
        }

    fun popSigner(
        clock: Clock = Clock.systemDefaultZone(),
        credentialConfiguration: CredentialConfiguration,
    ): PopSigner? =
        credentialConfiguration.proofTypesSupported.values.asSequence().mapNotNull {
            popSigner(clock, it)
        }.firstOrNull()
}

fun CoseAlgorithm.toNimbus(): JWSAlgorithm? = JWSAlgorithm.parse(name())

fun CoseCurve.toNimbus(): Curve? = Curve.parse(name())
