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

import com.authlete.cbor.*
import com.authlete.cose.*
import com.authlete.cwt.CWT
import com.authlete.cwt.CWTClaimsSet
import com.authlete.cwt.CWTKeyProofBuilder
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vci.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import java.security.Key
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.util.Date
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.*

/**
 * Test cases for [ProofBuilder].
 */
internal class ProofBuilderTest {

    @Test
    fun `proof is successfully generated when signing algorithm is supported by the issuer`() = runTest {
        val signingAlgorithm = JWSAlgorithm.RS256
        val credentialConfiguration = universityDegreeJwt()
        val proofTypeMeta = credentialConfiguration.proofTypesSupported
            .values.filterIsInstance<ProofTypeMeta.Jwt>()
            .firstOrNull()
        assertNotNull(proofTypeMeta)

        assertTrue { signingAlgorithm in proofTypeMeta.algorithms }

        val signer = CryptoGenerator.rsaProofSigner(signingAlgorithm)

        JwtProofBuilder(
            Clock.systemDefaultZone(),
            iss = "https://wallet",
            aud = CredentialIssuerId("https://issuer").getOrThrow(),
            nonce = CNonce("nonce"),
            signer,
        ).build()
    }

    @Test
    fun `proof is not generated when signing algorithm is not supported by the issuer`() = runTest {
        val signingAlgorithm = JWSAlgorithm.RS512
        val credentialConfiguration = universityDegreeJwt()
        val proofTypeMeta = credentialConfiguration.proofTypesSupported
            .values.filterIsInstance<ProofTypeMeta.Jwt>()
            .firstOrNull()
        assertNotNull(proofTypeMeta)
        assertFalse { signingAlgorithm in proofTypeMeta.algorithms }

        val signer = CryptoGenerator.rsaProofSigner(signingAlgorithm)
        assertFailsWith(CredentialIssuanceError.ProofGenerationError.ProofTypeSigningAlgorithmNotSupported::class) {
            JwtProofBuilder.check(signer, credentialConfiguration.proofTypesSupported)
        }
    }

    @Test
    fun `check cwt proof`() = runTest {
        val clock = Clock.fixed(Instant.now(), ZoneId.systemDefault())
        val proofTypeMeta = ProofTypeMeta.Cwt(listOf(CoseAlgorithm.ES256), listOf(CoseCurve.P_256))
        val (ecKey, popSigner) = checkNotNull(CryptoGenerator.keyAndPopSigner(clock, proofTypeMeta))
        assertIs<ECKey>(ecKey)
        assertIs<PopSigner.Cwt>(popSigner)
        val iss = "wallet"
        val aud = CredentialIssuerId("https://foo").getOrThrow()
        val cNonce = CNonce(Nonce().value)

        val cwt = CwtProofBuilder(clock, iss, aud, cNonce, popSigner).build()

        assertDoesNotThrow {
            CwtProofValidator.isValid(iss, aud, cNonce, clock.instant(), cwt).getOrThrow()
        }
    }

    @Test
    fun `check cwt proof with authlete impl`() = runTest {
        val clock = Clock.fixed(Instant.now(), ZoneId.systemDefault())
        val proofTypeMeta = ProofTypeMeta.Cwt(listOf(CoseAlgorithm.ES256), listOf(CoseCurve.P_256))
        val (ecKey, popSigner) = checkNotNull(CryptoGenerator.keyAndPopSigner(clock, proofTypeMeta))
        assertIs<ECKey>(ecKey)
        assertIs<PopSigner.Cwt>(popSigner)
        val iss = "wallet"
        val aud = CredentialIssuerId("https://foo").getOrThrow()
        val cNonce = CNonce(Nonce().value)

        val cwt = Proof.Cwt(
            CWTKeyProofBuilder().apply {
                issuer = aud.toString()
                issuedAt = Date.from(clock.instant())
                client = iss
                nonce = cNonce.value
                key = COSEEC2Key.fromJwk(ecKey.toJSONObject())
            }.build().encodeToBase64Url(),
        )

        assertDoesNotThrow {
            CwtProofValidator.isValid(iss, aud, cNonce, clock.instant(), cwt).getOrThrow()
        }
    }
}

internal object CwtProofValidator {

    fun isValid(
        iss: ClientId,
        aud: CredentialIssuerId,
        nonce: CNonce,
        iat: Instant,
        p: Proof.Cwt,
    ): Result<Unit> = runCatching {
        val claimSet = claimSet(p)
        require(iss == claimSet.iss) {
            "Invalid CWT proof. Expecting iss=$iss found ${claimSet.iss}"
        }
        require(aud.toString() == claimSet.aud) {
            "Invalid CWT proof. Expecting aud=$aud found ${claimSet.aud}"
        }
        require(nonce.value == claimSet.nonce.toString(Charsets.UTF_8)) {
            "Invalid CWT proof. Expecting nonce=${nonce.value}"
        }
        val claimSetIat = requireNotNull(claimSet.iat) {
            "Invalid CWT proof. Missing iat"
        }
        require(iat.epochSecond == claimSetIat.toInstant().epochSecond) {
            "Invalid CWT proof. Not mathcing iat"
        }
    }

    private fun claimSet(p: Proof.Cwt): CWTClaimsSet {
        val cwt = ensureIsCWT(p)
        val sign1 = ensureContainsSignOneMessage(cwt)
        verifySignature(sign1)
        return claimSet(sign1)
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun ensureIsCWT(p: Proof.Cwt): CWT {
        val cwtInBytes = Base64.UrlSafe.decode(p.cwt)
        val cborItem = CBORDecoder(cwtInBytes).next()
        require(cborItem is CWT) { "Not CBOR CWT" }
        return cborItem
    }

    private fun ensureContainsSignOneMessage(cwt: CWT): COSESign1 {
        val message = cwt.message
        require(message is COSESign1) { "CWT does not contain a COSE Sign one message" }
        return message
    }

    private fun verifySignature(sign1: COSESign1) {
        val coseKey = ensureValidProtectedHeader(sign1)
        require(COSEVerifier(coseKey).verify(sign1)) { "Invalid signature" }
    }

    private fun ensureValidProtectedHeader(sign1: COSESign1): Key {
        val pHeader: COSEProtectedHeader = sign1.protectedHeader
        require("openid4vci-proof+cwt" == pHeader.contentType) { "Invalid content type ${pHeader.contentType}" }

        val coseKey = run {
            val coseKeyAsByteString = pHeader.pairs.firstOrNull { (key, value) ->
                key is CBORString && key.value == "COSE_Key" &&
                    value is CBORByteArray
            }?.value as CBORByteArray?
            val cborItem = coseKeyAsByteString?.let { CBORDecoder(it.value).next() }

            cborItem?.takeIf { it is CBORPairList }?.let { item ->
                check(item is CBORPairList)
                COSEEC2Key(item.pairs)
            }
        }

        val x5cChain = pHeader.x5Chain.orEmpty()
        require(!(null != coseKey && x5cChain.isNotEmpty())) {
            "Cannot have both a COSE_Key and x5c chain"
        }
        return if (coseKey != null) {
            val authJwk = coseKey.toJwk()
            val jwk: JWK = JWK.parse(authJwk)
            require(jwk is ECKey)
            jwk.toPublicKey()
        } else {
            x5cChain.first().publicKey
        }
    }

    private fun claimSet(sign1: COSESign1): CWTClaimsSet {
        val payload = sign1.payload
        val parsed = payload.parse()
        val listOfPairs = CBORDecoder(parsed as ByteArray).next() as CBORPairList
        return CWTClaimsSet(listOfPairs.pairs)
    }
}

private operator fun CBORPair.component1(): CBORItem = key
private operator fun CBORPair.component2(): CBORItem = value
