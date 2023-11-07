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
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.time.Instant
import java.util.*
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

sealed interface ProofBuilder {

    fun alg(alg: JWSAlgorithm)
    fun jwk(jwk: JWK)
    fun iss(iss: String)
    fun aud(aud: String)
    fun nonce(nonce: String)
    fun build(): Proof

    private class JwtProofBuilder : ProofBuilder {

        val HEADER_TYPE = "openid4vci-proof+jwt"
        val claimsSet = JWTClaimsSet.Builder()
        var alg: JWSAlgorithm? = null
        var jwk: JWK? = null

        override fun alg(alg: JWSAlgorithm) {
            this.alg = alg
        }

        override fun jwk(jwk: JWK) {
            this.jwk = jwk
        }

        override fun iss(iss: String) {
            claimsSet.issuer(iss)
        }

        override fun aud(aud: String) {
            claimsSet.audience(aud)
        }

        override fun nonce(nonce: String) {
            claimsSet.claim("nonce", nonce)
        }

        override fun build(): Proof.Jwt {
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

            return Proof.Jwt(signedJWT)
        }
    }

    companion object {
        @OptIn(ExperimentalContracts::class)
        fun ofType(type: ProofType, usage: ProofBuilder.() -> Proof): Proof {
            contract {
                callsInPlace(usage, InvocationKind.EXACTLY_ONCE)
            }
            return when (type) {
                ProofType.JWT -> {
                    with(JwtProofBuilder()) {
                        usage()
                    }
                }

                ProofType.CWT -> TODO("CWT proofs not supported yet")
            }
        }
    }
}
