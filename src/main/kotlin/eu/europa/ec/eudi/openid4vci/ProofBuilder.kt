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
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Instant
import java.util.*

sealed interface ProofBuilder {

    class JwtProofBuilder : ProofBuilder {

        val HEADER_TYPE = "openid4vci-proof+jwt"

        val claimsSet = JWTClaimsSet.Builder()

        var alg: JWSAlgorithm? = null
        var jwk: JWK? = null

        fun alg(alg: JWSAlgorithm): JwtProofBuilder {
            this.alg = alg
            return this
        }

        fun jwk(jwk: JWK): JwtProofBuilder {
            this.jwk = jwk
            return this
        }

        fun iss(iss: String): JwtProofBuilder {
            claimsSet.issuer(iss)
            return this
        }
        fun aud(aud: String): JwtProofBuilder {
            claimsSet.audience(aud)
            return this
        }
        fun nonce(nonce: String): JwtProofBuilder {
            claimsSet.claim("nonce", nonce)
            return this
        }

        fun build(): SignedJWT {
            checkNotNull(alg) {
                "No signing algorithm provided"
            }
            checkNotNull(jwk) {
                "Cryptographic key material must be provided"
            }
            check(jwk?.keyType == KeyType.forAlgorithm(alg)) {
                "Provided key and signing algorithm do not match"
            }
            checkNotNull(claimsSet.claims["aud"]) {
                "Claim 'aud' is missing"
            }
            checkNotNull(claimsSet.claims["nonce"]) {
                "Claim 'nonce' is missing"
            }

            val headerBuilder = JWSHeader.Builder(alg)
            headerBuilder.type(JOSEObjectType(HEADER_TYPE))
            headerBuilder.jwk(jwk!!.toPublicJWK())

            claimsSet.issueTime(Date.from(Instant.now()))

            val signedJWT = SignedJWT(headerBuilder.build(), claimsSet.build())
            val signer = DefaultJWSSignerFactory().createJWSSigner(jwk!!, alg)
            signedJWT.sign(signer)

            return signedJWT
        }
    }

    companion object {
        fun ofType(type: ProofType) =
            when (type) {
                ProofType.JWT -> JwtProofBuilder()
                ProofType.CWT -> TODO("CWT proofs not supported yet")
            }

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
    }
}
