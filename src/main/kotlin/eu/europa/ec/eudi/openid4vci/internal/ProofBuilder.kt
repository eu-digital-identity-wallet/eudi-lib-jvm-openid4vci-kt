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
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.*
import java.time.Instant
import java.util.*

internal sealed interface ProofBuilder<in POPSigner : PopSigner, out PROOF : Proof> {
    fun iss(iss: String)
    fun aud(aud: String)
    fun nonce(nonce: String)
    fun credentialSpec(credentialSpec: CredentialConfiguration)
    fun build(proofSigner: POPSigner): PROOF

    class JwtProofBuilder() : ProofBuilder<PopSigner.Jwt, Proof.Jwt> {

        private val headerType = "openid4vci-proof+jwt"
        private val claimsSet = JWTClaimsSet.Builder()

        private var credentialSpec: CredentialConfiguration? = null

        override fun iss(iss: String) {
            claimsSet.issuer(iss)
        }

        override fun aud(aud: String) {
            claimsSet.audience(aud)
        }

        override fun nonce(nonce: String) {
            claimsSet.claim("nonce", nonce)
        }

        override fun credentialSpec(credentialSpec: CredentialConfiguration) {
            this.credentialSpec = credentialSpec
        }

        override fun build(proofSigner: PopSigner.Jwt): Proof.Jwt {
            val spec = checkNotNull(credentialSpec) {
                "No credential specification provided"
            }
            val proofTypesSupported = spec.proofTypesSupported
            val jwtProofTypeMeta = proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
            ensureNotNull(jwtProofTypeMeta) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
            }
            val proofTypeSigningAlgorithmsSupported = jwtProofTypeMeta.algorithms
            ensure(proofSigner.algorithm in proofTypeSigningAlgorithmsSupported) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported
            }
            val header = run {
                val algorithm = proofSigner.algorithm
                val headerBuilder = JWSHeader.Builder(algorithm)
                headerBuilder.type(JOSEObjectType(headerType))
                when (val key = proofSigner.bindingKey) {
                    is JwtBindingKey.Jwk -> headerBuilder.jwk(key.jwk.toPublicJWK())
                    is JwtBindingKey.Did -> headerBuilder.keyID(key.identity)
                    is JwtBindingKey.X509 -> headerBuilder.x509CertChain(key.chain.map { Base64.encode(it.encoded) })
                }
                headerBuilder.build()
            }
            val claims = run {
                checkNotNull(claimsSet.claims["aud"]) { "Claim 'aud' is missing" }
                checkNotNull(claimsSet.claims["nonce"]) { "Claim 'nonce' is missing" }
                claimsSet.issueTime(Date.from(Instant.now()))
                claimsSet.build()
            }
            val signedJWT = SignedJWT(header, claims).apply { sign(proofSigner.signer) }
            return Proof.Jwt(signedJWT)
        }
    }
}
