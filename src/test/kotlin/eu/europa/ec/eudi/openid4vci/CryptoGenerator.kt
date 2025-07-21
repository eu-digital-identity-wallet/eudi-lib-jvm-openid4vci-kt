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
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT.Companion.KEY_ATTESTATION_JWT_TYPE
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKey
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKeys
import java.security.Signature
import java.time.Instant.now
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

    fun rsaProofSigner(signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): PopSigner.Jwt =
        rsaKeyAndJwtProofSigner(signingAlgorithm).second

    fun rsaKeyAndJwtProofSigner(signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256): Pair<JWK, PopSigner.Jwt> {
        val keyPair = randomRSASigningKey(2048)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return keyPair to PopSigner.jwtPopSigner(keyPair, signingAlgorithm, bindingKey)
    }

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

    fun ecKeyAndJwtProofSigner(
        curve: Curve = Curve.P_256,
        alg: JWSAlgorithm = JWSAlgorithm.ES256,
    ): Pair<JWK, PopSigner.Jwt> {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = JwtBindingKey.Jwk(keyPair.toPublicJWK())
        return keyPair to PopSigner.jwtPopSigner(keyPair, alg, bindingKey)
    }

    private fun CoseAlgorithm.signature(): Signature =
        when (this) {
            CoseAlgorithm.ES256 -> "SHA256withECDSAinP1363Format"
            CoseAlgorithm.ES384 -> "SHA384withECDSAinP1363Format"
            CoseAlgorithm.ES512 -> "SHA512withECDSAinP1363Format"
            else -> error("Unsupported $this")
        }.let { Signature.getInstance(it) }

    fun keyAndPopSigner(
        proofTypeMeta: ProofTypeMeta,
    ): Pair<JWK, PopSigner>? =
        when (proofTypeMeta) {
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
            is ProofTypeMeta.Unsupported -> null
        }

    fun popSigner(
        credentialConfiguration: CredentialConfiguration,
    ): PopSigner? =
        credentialConfiguration.proofTypesSupported.values
            .firstNotNullOfOrNull { keyAndPopSigner(it)?.second }

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
    ): ProofsSpecification {
        val ecKeys = List(3) { randomECSigningKey(curve) }
        val signer = Signer.fromNimbusEcKey(
            ecPrivateKey = ecKeys[0],
            keyInfo = keyAttestationJwtEC(
                attestedKeys = ecKeys.map { it.toPublicJWK() },
            ),
            secureRandom = null,
            provider = null,
        )
        return ProofsSpecification.JwtProofs.WithKeyAttestation(signer, 1)
    }

    fun keyAttestationJwtEC(
        attestedKeys: List<JWK>,
    ) = run {
        val ecKey = randomECSigningKey(Curve.P_256)
        val jwt = randomKeyAttestationJwt(
            attestedKeys = attestedKeys,
            jwk = ecKey.toPublicJWK(),
            signer = ECDSASigner(ecKey.toECKey()),
        )
        KeyAttestationJWT(jwt.serialize())
    }

    fun keyAttestationJwtRsa(
        attestedKeys: List<JWK>,
    ) = run {
        val rsaKey = randomRSASigningKey(256)
        val jwt = randomKeyAttestationJwt(
            attestedKeys = attestedKeys,
            jwk = rsaKey.toPublicJWK(),
            signer = RSASSASigner(rsaKey),
        )
        KeyAttestationJWT(jwt.serialize())
    }

    private fun randomKeyAttestationJwt(
        attestedKeys: List<JWK>,
        jwk: JWK,
        signer: JWSSigner,
    ): SignedJWT = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(KEY_ATTESTATION_JWT_TYPE))
            .jwk(jwk)
            .build(),
        JWTClaimsSet.Builder().apply {
            issueTime(Date.from(now()))
            claim("attested_keys", attestedKeys.map { it.toJSONObject() })
            expirationTime(Date.from(now().plusSeconds(3600)))
        }.build(),
    ).apply { sign(signer) }
}
