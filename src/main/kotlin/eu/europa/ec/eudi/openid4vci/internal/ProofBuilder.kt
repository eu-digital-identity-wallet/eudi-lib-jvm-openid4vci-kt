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
import java.time.Clock
import java.util.*

private interface CheckPopSigner<POP_SIGNER : PopSigner> {
    fun check(popSigner: POP_SIGNER, proofTypesSupported: ProofTypesSupported)
}

internal abstract class ProofBuilder<POP_SIGNER : PopSigner, out PROOF : Proof>(
    val clock: Clock,
    val iss: ClientId?,
    val aud: CredentialIssuerId,
    val nonce: CNonce?,
    val popSigner: POP_SIGNER,
) {

    abstract suspend fun build(): PROOF

    companion object {
        operator fun invoke(
            proofTypesSupported: ProofTypesSupported,
            clock: Clock,
            iss: ClientId?,
            aud: CredentialIssuerId,
            nonce: CNonce?,
            popSigner: PopSigner,
        ): ProofBuilder<*, *> {
            return when (popSigner) {
                is PopSigner.Jwt -> {
                    JwtProofBuilder.check(popSigner, proofTypesSupported)
                    JwtProofBuilder(clock, iss, aud, nonce, popSigner)
                }
            }
        }
        operator fun invoke(
            proofTypesSupported: ProofTypesSupported,
            clock: Clock,
            client: Client,
            grant: Grant,
            aud: CredentialIssuerId,
            nonce: CNonce?,
            popSigner: PopSigner,
        ): ProofBuilder<*, *> =
            invoke(proofTypesSupported, clock, iss(client, grant), aud, nonce, popSigner)

        private fun iss(client: Client, grant: Grant): ClientId? {
            val useIss = when (grant) {
                Grant.AuthorizationCode -> true
                Grant.PreAuthorizedCodeGrant -> when (client) {
                    is Client.Attested -> true
                    is Client.Public -> false
                }
            }
            return client.id.takeIf { useIss }
        }
    }
}

internal class JwtProofBuilder(
    clock: Clock,
    iss: ClientId?,
    aud: CredentialIssuerId,
    nonce: CNonce?,
    popSigner: PopSigner.Jwt,
) : ProofBuilder<PopSigner.Jwt, Proof.Jwt>(clock, iss, aud, nonce, popSigner) {

    override suspend fun build(): Proof.Jwt {
        val header = header()
        val claimSet = claimSet()
        val jwt = SignedJWT(header, claimSet).apply { sign(popSigner.jwsSigner) }
        return Proof.Jwt(jwt)
    }

    private fun header(): JWSHeader {
        val algorithm = popSigner.algorithm
        val headerBuilder = JWSHeader.Builder(algorithm)
        headerBuilder.type(JOSEObjectType(HEADER_TYPE))
        when (val key = popSigner.bindingKey) {
            is JwtBindingKey.Jwk -> headerBuilder.jwk(key.jwk.toPublicJWK())
            is JwtBindingKey.Did -> headerBuilder.keyID(key.identity)
            is JwtBindingKey.X509 -> headerBuilder.x509CertChain(key.chain.map { Base64.encode(it.encoded) })
        }
        return headerBuilder.build()
    }

    private fun claimSet(): JWTClaimsSet =
        JWTClaimsSet.Builder().apply {
            iss?.let { issuer(it) }
            audience(aud.toString())
            nonce?.let { claim("nonce", nonce.value) }
            issueTime(Date.from(clock.instant()))
        }.build()

    companion object : CheckPopSigner<PopSigner.Jwt> {

        private const val HEADER_TYPE = "openid4vci-proof+jwt"

        override fun check(popSigner: PopSigner.Jwt, proofTypesSupported: ProofTypesSupported) {
            val spec = proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
            ensureNotNull(spec) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported()
            }
            val proofTypeSigningAlgorithmsSupported = spec.algorithms
            ensure(popSigner.algorithm in proofTypeSigningAlgorithmsSupported) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported()
            }
        }
    }
}
