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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKey
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKeys
import java.time.Instant.now
import java.util.*

object CryptoGenerator {

    fun randomECSigningKey(curve: Curve): ECKey = ECKeyGenerator(curve)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun ecSigner(curve: Curve = Curve.P_256, alg: JWSAlgorithm = JWSAlgorithm.ES256): Signer<JWK> {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        return Signer.fromNimbusEcKey(
            keyPair,
            keyPair.toPublicJWK(),
            secureRandom = null,
            provider = null,
        )
    }

    fun proofsSpecForEcKeys(
        curve: Curve = Curve.P_256,
        num: Int = 1,
    ): ProofsSpecification.JwtProofs.NoKeyAttestation {
        val ecKeys = List(num) { randomECSigningKey(curve) }
        val batchSigner = BatchSigner.fromNimbusEcKeys(
            ecKeyPairs = ecKeys.associateWith { JwtBindingKey.Jwk(it.toPublicJWK()) },
            secureRandom = null,
            provider = null,
        )
        return ProofsSpecification.JwtProofs.NoKeyAttestation(batchSigner)
    }

    fun keyAttestationJwtProofsSpec(
        curve: Curve = Curve.P_256,
        attestedKeysCount: Int = 3,
    ): ProofsSpecification {
        val ecKeys = List(attestedKeysCount) { randomECSigningKey(curve) }
        val signer = Signer.fromNimbusEcKey(
            ecPrivateKey = ecKeys[0],
            keyInfo = keyAttestationJwt(
                attestedKeys = ecKeys.map { it.toPublicJWK() },
            ),
            secureRandom = null,
            provider = null,
        )
        return ProofsSpecification.JwtProofs.WithKeyAttestation(signer, 1)
    }

    fun keyAttestationJwt(
        attestedKeys: List<JWK>,
    ) = run {
        val signingKey = randomECSigningKey(Curve.P_256)
        val jwt = randomKeyAttestationJwt(
            attestedKeys = attestedKeys,
            jwk = signingKey.toPublicJWK(),
            signer = ECDSASigner(signingKey),
        )
        KeyAttestationJWT(jwt.serialize())
    }

    fun randomKeyAttestationJwt(): SignedJWT {
        val attestedKeys = List(3) { randomECSigningKey(Curve.P_256) }
        val signingKey = randomECSigningKey(Curve.P_256)
        return randomKeyAttestationJwt(
            attestedKeys = attestedKeys.map { it.toPublicJWK() },
            jwk = signingKey.toPublicJWK(),
            signer = ECDSASigner(signingKey),
        )
    }

    private fun randomKeyAttestationJwt(
        attestedKeys: List<JWK>,
        jwk: JWK,
        signer: JWSSigner,
    ): SignedJWT = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(OpenId4VPSpec.KEY_ATTESTATION_JWT_TYPE))
            .jwk(jwk)
            .build(),
        JWTClaimsSet.Builder().apply {
            claim("attested_keys", attestedKeys.map { it.toJSONObject() })
            claim("key_storage", listOf("iso_18045_moderate"))
            claim("user_authentication", listOf("iso_18045_moderate"))
            issueTime(Date.from(now()))
            expirationTime(Date.from(now().plusSeconds(3600)))
        }.build(),
    ).apply { sign(signer) }
}
