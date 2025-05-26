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
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT.Companion.KEY_ATTESTATION_JWT_TYPE
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

    fun rsaProofSigner(
        signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256,
        bindingKeyProvider: (JWK) -> JwtBindingKey = { JwtBindingKey.Jwk(it.toPublicJWK()) },
    ): PopSigner.Jwt =
        rsaKeyAndJwtProofSigner(signingAlgorithm, bindingKeyProvider).second

    fun rsaKeyAndJwtProofSigner(
        signingAlgorithm: JWSAlgorithm = JWSAlgorithm.RS256,
        bindingKeyProvider: (JWK) -> JwtBindingKey = { JwtBindingKey.Jwk(it.toPublicJWK()) },
    ): Pair<JWK, PopSigner.Jwt> {
        val keyPair = randomRSASigningKey(2048)
        val bindingKey = bindingKeyProvider(keyPair)
        return keyPair to PopSigner.jwtPopSigner(keyPair, signingAlgorithm, bindingKey)
    }

    fun ecProofSigner(
        curve: Curve = Curve.P_256,
        alg: JWSAlgorithm = JWSAlgorithm.ES256,
        bindingKeyProvider: (JWK) -> JwtBindingKey = { JwtBindingKey.Jwk(it.toPublicJWK()) },
    ): PopSigner.Jwt {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = bindingKeyProvider(keyPair)
        return PopSigner.jwtPopSigner(keyPair, alg, bindingKey)
    }

    fun ecKeyAndJwtProofSigner(
        curve: Curve = Curve.P_256,
        alg: JWSAlgorithm = JWSAlgorithm.ES256,
        bindingKeyProvider: (JWK) -> JwtBindingKey = { JwtBindingKey.Jwk(it.toPublicJWK()) },
    ): Pair<JWK, PopSigner.Jwt> {
        require(alg in JWSAlgorithm.Family.EC)
        val keyPair = randomECSigningKey(curve)
        val bindingKey = bindingKeyProvider(keyPair)
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

    fun keyAttestationJwt(
        alg: JWSAlgorithm = JWSAlgorithm.ES256,
        jwk: JWK,
        signer: JWSSigner,
    ) = run {
        val signedJwt = SignedJWT(
            JWSHeader.Builder(alg)
                .type(JOSEObjectType(KEY_ATTESTATION_JWT_TYPE))
                .build(),
            JWTClaimsSet.Builder()
                .issueTime(Date())
                .claim("attested_keys", listOf(jwk.toPublicJWK().toJSONObject()))
                .expirationTime(Date.from(now().plus(java.time.Duration.ofSeconds(60))))
                .build(),
        )
        signedJwt.sign(signer)
        KeyAttestationJWT(signedJwt)
    }
}
