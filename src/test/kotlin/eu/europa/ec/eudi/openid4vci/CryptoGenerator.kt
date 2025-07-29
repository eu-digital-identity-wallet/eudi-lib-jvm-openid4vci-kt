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
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
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
        keysNo: Int = 1,
    ): ProofsSpecification {
        val ecKeys = List(keysNo) { randomECSigningKey(curve) }
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

    fun attestationProofSpec(keysNo: Int = 3) =
        ProofsSpecification.AttestationProof(
            keyAttestationJwt(
                List(keysNo) {
                    randomECSigningKey(Curve.P_256)
                },
            ),
        )

    // Helper to load an EC private key from PEM file
    private fun loadECPrivateKeyFromFile(resourcePath: String): ECPrivateKey {
        val pem = CryptoGenerator::class.java.classLoader.getResource(resourcePath)?.readText()
            ?: error("Private key file not found: $resourcePath")
        val base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\r", "")
            .replace("\n", "")
            .trim()
        val keyBytes = Base64.getDecoder().decode(base64)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("EC")
        return kf.generatePrivate(keySpec) as ECPrivateKey
    }

    // Helper to load X.509 certificate from PEM file
    private fun loadCertificateFromFile(resourcePath: String): X509Certificate {
        val certStream = CryptoGenerator::class.java.classLoader.getResourceAsStream(resourcePath)
            ?: error("Certificate file not found: $resourcePath")
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(certStream) as X509Certificate
    }

    fun keyAttestationJwt(
        attestedKeys: List<JWK>? = null,
    ) = run {
        val privateKey = loadECPrivateKeyFromFile("eu/europa/ec/eudi/openid4vci/internal/key_attestation_jwt.key")
        val certificate = loadCertificateFromFile("eu/europa/ec/eudi/openid4vci/internal/key_attestation_jwt.cert")
        val jwt = keyAttestationJwt(
            attestedKeys = attestedKeys ?: List(3) { randomECSigningKey(Curve.P_256) },
            certificate = certificate,
            signer = ECDSASigner(privateKey),
        )
        KeyAttestationJWT(jwt.serialize())
    }

    private fun keyAttestationJwt(
        attestedKeys: List<JWK>,
        certificate: X509Certificate,
        signer: JWSSigner,
    ): SignedJWT = SignedJWT(
        JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(OpenId4VPSpec.KEY_ATTESTATION_JWT_TYPE))
            .x509CertChain(listOf(com.nimbusds.jose.util.Base64.encode(certificate.encoded)))
            .build(),
        JWTClaimsSet.Builder().apply {
            claim(OpenId4VPSpec.KEY_ATTESTATION_ATTESTED_KEYS, attestedKeys.map { it.toPublicJWK().toJSONObject() })
            claim(OpenId4VPSpec.KEY_ATTESTATION_KEY_STORAGE, listOf("iso_18045_moderate"))
            claim(OpenId4VPSpec.KEY_ATTESTATION_USER_AUTHENTICATION, listOf("iso_18045_moderate"))
            issueTime(Date.from(now()))
            expirationTime(Date.from(now().plusSeconds(3600)))
        }.build(),
    ).apply { sign(signer) }
}
