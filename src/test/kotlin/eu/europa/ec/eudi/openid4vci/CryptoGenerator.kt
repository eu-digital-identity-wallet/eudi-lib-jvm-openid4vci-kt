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
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import java.security.Signature
import java.time.Clock
import java.util.*
import kotlin.Comparator

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

    fun rsaProofSigner(signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): PopSigner.Jwt =
        rsaKeyAndJwtProofSigner(signingAlgorithm).second

    fun rsaKeyAndJwtProofSigner(signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): Pair<JWK, PopSigner.Jwt> {
        val keyPair = randomRSASigningKey(2048)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return keyPair to PopSigner.jwtPopSigner(keyPair, signingAlgorithm, bindingKey)
    }

    fun ecProofSigner(curve: Curve = Curve.P_256, alg: JWSAlgorithm = JWSAlgorithm.ES256): PopSigner.Jwt {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return PopSigner.jwtPopSigner(keyPair, alg, bindingKey)
    }

    fun ecKeyAndJwtProofSigner(curve: Curve = Curve.P_256, alg: JWSAlgorithm = JWSAlgorithm.ES256): Pair<JWK, PopSigner.Jwt> {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return keyPair to PopSigner.jwtPopSigner(keyPair, alg, bindingKey)
    }

    @Deprecated(
        message = "CWT proofs have been removed from OpenId4VCI",
    )
    private fun ecKeyAndCwtPopSigner(
        clock: Clock,
        alg: CoseAlgorithm,
        curve: CoseCurve,
        kid: String,
    ): Pair<JWK, PopSigner.Cwt> {
        val keyPair: ECKey = ECKeyGenerator(checkNotNull(curve.toNimbus()))
            .keyUse(KeyUse.SIGNATURE)
            .keyID(kid)
            .algorithm(checkNotNull(alg.toNimbus()))
            .issueTime(Date.from(clock.instant()))
            .generate()

//        val publicJwk = keyPair.toPublicJWK()
//        val bindingKey = CwtBindingKey.CoseKey(publicJwk)
//        val popSigner = PopSigner.Cwt(alg, curve, bindingKey) { data ->
//            with(alg.signature()) {
//                initSign(keyPair.toECPrivateKey())
//                update(data)
//                sign()
//            }
//        }
        val popSigner = PopSigner.cwtPopSigner(keyPair)
        return keyPair to popSigner
    }

    private fun CoseAlgorithm.signature(): Signature =
        when (this) {
            CoseAlgorithm.ES256 -> "SHA256withECDSAinP1363Format"
            CoseAlgorithm.ES384 -> "SHA384withECDSAinP1363Format"
            CoseAlgorithm.ES512 -> "SHA512withECDSAinP1363Format"
            else -> error("Unsupported $this")
        }.let { Signature.getInstance(it) }

    fun keyAndPopSigner(
        clock: Clock = Clock.systemDefaultZone(),
        proofTypeMeta: ProofTypeMeta,
        kid: String = UUID.randomUUID().toString(),
    ): Pair<JWK, PopSigner>? =
        when (proofTypeMeta) {
            is ProofTypeMeta.Cwt -> {
                val supported: List<Pair<CoseAlgorithm, CoseCurve>> = proofTypeMeta.algorithms.zip(proofTypeMeta.curves)
                sequenceOf(
                    CoseAlgorithm.ES256 to CoseCurve.P_256,
                    CoseAlgorithm.ES384 to CoseCurve.P_384,
                    CoseAlgorithm.ES512 to CoseCurve.P_521,
                ).firstOrNull { it in supported }?.let { (a, c) ->
                    ecKeyAndCwtPopSigner(clock = clock, alg = a, curve = c, kid = kid)
                }
            }

            is ProofTypeMeta.Jwt -> {
                proofTypeMeta.algorithms.asSequence().mapNotNull { alg ->
                    when (alg) {
                        JWSAlgorithm.ES256 -> ecKeyAndJwtProofSigner(Curve.P_256, alg)
                        JWSAlgorithm.ES384 -> ecKeyAndJwtProofSigner(Curve.P_384, alg)
                        JWSAlgorithm.ES512 -> ecKeyAndJwtProofSigner(Curve.P_521, alg)
                        in JWSAlgorithm.Family.RSA -> rsaKeyAndJwtProofSigner(alg)
                        else -> null
                    }
                }.firstOrNull()
            }

            ProofTypeMeta.LdpVp -> null
        }

    fun popSigner(
        clock: Clock = Clock.systemDefaultZone(),
        credentialConfiguration: CredentialConfiguration,
        preference: ProofTypeMetaPreference,
    ): PopSigner? =
        credentialConfiguration.proofTypesSupported.values.sortedWith(preference.comparator().reversed())
            .firstNotNullOfOrNull { keyAndPopSigner(clock, it)?.second }
}

enum class ProofTypeMetaPreference {
    FavorJWT,
    FavorCWT,
    ;

    fun comparator(): Comparator<ProofTypeMeta> = when (this) {
        FavorJWT -> comparatorFavoring<ProofTypeMeta.Jwt>()
        FavorCWT -> comparatorFavoring<ProofTypeMeta.Cwt>()
    }

    private inline fun <reified T : ProofTypeMeta>comparatorFavoring(): Comparator<ProofTypeMeta> = Comparator { a, b ->
        when {
            a is T -> 1
            b is T -> -1
            else -> 0
        }
    }
}

fun CoseAlgorithm.toNimbus(): JWSAlgorithm? = JWSAlgorithm.parse(name())

fun CoseCurve.toNimbus(): Curve? = Curve.parse(name())
