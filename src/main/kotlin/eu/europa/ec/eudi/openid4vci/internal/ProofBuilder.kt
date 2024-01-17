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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import java.time.Instant
import java.util.*
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

internal sealed interface ProofBuilder {
    fun iss(iss: String)
    fun aud(aud: String)
    fun nonce(nonce: String)
    fun publicKey(publicKey: BindingKey)
    fun credentialSpec(credentialSpec: CredentialSupported)

    fun build(proofSigner: ProofSigner): Proof

    private class JwtProofBuilder : ProofBuilder {

        private val headerType = "openid4vci-proof+jwt"
        val claimsSet = JWTClaimsSet.Builder()
        var publicKey: BindingKey? = null
        var credentialSpec: CredentialSupported? = null

        override fun iss(iss: String) {
            claimsSet.issuer(iss)
        }

        override fun aud(aud: String) {
            claimsSet.audience(aud)
        }

        override fun nonce(nonce: String) {
            claimsSet.claim("nonce", nonce)
        }

        override fun publicKey(publicKey: BindingKey) {
            this.publicKey = publicKey
        }

        override fun credentialSpec(credentialSpec: CredentialSupported) {
            this.credentialSpec = credentialSpec
        }

        override fun build(proofSigner: ProofSigner): Proof.Jwt {
            val algorithm = proofSigner.getAlgorithm()

            validate(algorithm)

            val headerBuilder = JWSHeader.Builder(algorithm)
            headerBuilder.type(JOSEObjectType(headerType))

            when (val key = publicKey!!) {
                is BindingKey.Jwk -> headerBuilder.jwk(key.jwk.toPublicJWK())
                is BindingKey.Did -> headerBuilder.keyID(key.identity)
                is BindingKey.X509 -> headerBuilder.x509CertChain(key.chain.map { Base64.encode(it.encoded) })
            }

            claimsSet.issueTime(Date.from(Instant.now()))

            val signedJWT = SignedJWT(headerBuilder.build(), claimsSet.build())
            signedJWT.sign(proofSigner)

            return Proof.Jwt(signedJWT)
        }

        private fun validate(algorithm: JWSAlgorithm) {
            checkNotNull(credentialSpec) {
                "No credential specification provided"
            }
            checkNotNull(publicKey) {
                "No public key provided"
            }
            checkNotNull(claimsSet.claims["aud"]) {
                "Claim 'aud' is missing"
            }
            checkNotNull(claimsSet.claims["nonce"]) {
                "Claim 'nonce' is missing"
            }
            if (!credentialSpec!!.cryptographicSuitesSupported.contains(algorithm.name)) {
                throw CredentialIssuanceError.ProofGenerationError.CryptographicSuiteNotSupported
            }
            if (!credentialSpec!!.proofTypesSupported.contains(ProofType.JWT)) {
                throw CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
            }
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
