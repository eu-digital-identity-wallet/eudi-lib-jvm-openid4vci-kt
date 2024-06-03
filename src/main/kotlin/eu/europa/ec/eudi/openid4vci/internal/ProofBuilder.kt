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

import com.authlete.cbor.CBORByteArray
import com.authlete.cose.*
import com.authlete.cwt.CWT
import com.authlete.cwt.CWTClaimsSetBuilder
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
    val iss: ClientId,
    val aud: CredentialIssuerId,
    val nonce: CNonce,
    val popSigner: POP_SIGNER,
) {

    abstract suspend fun build(): PROOF

    companion object {
        operator fun invoke(
            proofTypesSupported: ProofTypesSupported,
            clock: Clock,
            iss: ClientId,
            aud: CredentialIssuerId,
            nonce: CNonce,
            popSigner: PopSigner,
        ): ProofBuilder<*, *> {
            return when (popSigner) {
                is PopSigner.Jwt -> {
                    JwtProofBuilder.check(popSigner, proofTypesSupported)
                    JwtProofBuilder(clock, iss, aud, nonce, popSigner)
                }

                is PopSigner.Cwt -> {
                    CwtProofBuilder.check(popSigner, proofTypesSupported)
                    CwtProofBuilder(clock, iss, aud, nonce, popSigner)
                }
            }
        }
    }
}

internal class JwtProofBuilder(
    clock: Clock,
    iss: ClientId,
    aud: CredentialIssuerId,
    nonce: CNonce,
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
            issuer(iss)
            audience(aud.toString())
            claim("nonce", nonce.value)
            issueTime(Date.from(clock.instant()))
        }.build()

    companion object : CheckPopSigner<PopSigner.Jwt> {

        private const val HEADER_TYPE = "openid4vci-proof+jwt"

        override fun check(popSigner: PopSigner.Jwt, proofTypesSupported: ProofTypesSupported) {
            val spec = proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Jwt>().firstOrNull()
            ensureNotNull(spec) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
            }
            val proofTypeSigningAlgorithmsSupported = spec.algorithms
            ensure(popSigner.algorithm in proofTypeSigningAlgorithmsSupported) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported
            }
        }
    }
}

internal class CwtProofBuilder(
    clock: Clock,
    iss: ClientId,
    aud: CredentialIssuerId,
    nonce: CNonce,
    popSigner: PopSigner.Cwt,
) : ProofBuilder<PopSigner.Cwt, Proof.Cwt>(clock, iss, aud, nonce, popSigner) {

    override suspend fun build(): Proof.Cwt {
        val protectedHeader = protectedHeader()
        val payload = payload()
        val structure = sigStructure(protectedHeader, payload)
        val signature: ByteArray = popSigner.sign(structure.encode())
        val sign1 = sign1(protectedHeader, payload, signature)
        val cwt = CWT(sign1)
        return Proof.Cwt(cwt.encodeToBase64Url())
    }

    private fun protectedHeader(): COSEProtectedHeader =
        COSEProtectedHeaderBuilder().apply {
            alg(popSigner.algorithm.value)
            contentType(HEADER_TYPE)
            when (val bindingKey = popSigner.bindingKey) {
                is CwtBindingKey.CoseKey -> {
                    val key = COSEKey.fromJwk(bindingKey.jwk.toJSONObject())
                    put("COSE_Key", key)
                }

                is CwtBindingKey.X509 -> error("Not supported yet")
            }
        }.build()

    private fun payload(): CBORByteArray {
        val claims = CWTClaimsSetBuilder().apply {
            // Claim Key 1 (iss)
            iss(iss)
            // Claim Key 3 (aud)
            aud(aud.toString())
            // Claim Key 6 (iat)
            iat(Date.from(clock.instant()))
            // Claim Key 10 (Nonce)
            nonce(nonce.value)
        }.build()
        return CBORByteArray(claims.encode())
    }

    private fun sigStructure(
        protectedHeader: COSEProtectedHeader,
        payload: CBORByteArray,
    ): SigStructure = SigStructureBuilder()
        .signature1()
        .bodyAttributes(protectedHeader)
        .payload(payload)
        .build()

    private fun sign1(
        protectedHeader: COSEProtectedHeader,
        payload: CBORByteArray,
        signature: ByteArray,
    ): COSESign1 =
        COSESign1Builder()
            .protectedHeader(protectedHeader)
            .payload(payload)
            .signature(signature)
            .build()

    companion object : CheckPopSigner<PopSigner.Cwt> {

        private const val HEADER_TYPE = "openid4vci-proof+cwt"
        override fun check(popSigner: PopSigner.Cwt, proofTypesSupported: ProofTypesSupported) {
            val spec = proofTypesSupported.values.filterIsInstance<ProofTypeMeta.Cwt>().firstOrNull()
            ensureNotNull(spec) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeNotSupported
            }
            ensure(popSigner.algorithm in spec.algorithms) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported
            }
            ensure(popSigner.curve in spec.curves) {
                CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported
            }
        }
    }
}
