/*
 * Copyright (c) 2023-2026 European Commission
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

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.CertOps
import eu.europa.ec.eudi.openid4vci.CertOps.toX509Certificate
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.randomECSigningKey
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import org.bouncycastle.asn1.x500.X500Name
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotSame
import kotlin.test.assertTrue

class BatchIdentityTest {
    private fun selfSigned(
        keyPair: KeyPair,
        sigAlg: String = "SHA256withECDSA",
    ): X509Certificate = CertOps.createTrustAnchor(keyPair, sigAlg, X500Name("CN=Binding Key")).toX509Certificate()

    // Parsed again from its encoding, so that the two certificates share no objects.
    private fun X509Certificate.copy(): X509Certificate =
        java.security.cert.CertificateFactory
            .getInstance("X.509")
            .generateCertificate(encoded.inputStream()) as X509Certificate

    @Test
    fun `two certificates for the same key have the same identity`() {
        val certificate = selfSigned(randomECSigningKey(Curve.P_256).toKeyPair())
        val copy = certificate.copy()
        assertNotSame(certificate.publicKey.encoded, copy.publicKey.encoded)

        assertEquals(
            JwtBindingKey.X509(listOf(certificate)).batchIdentity(),
            JwtBindingKey.X509(listOf(copy)).batchIdentity(),
        )
    }

    @Test
    fun `a JWK and a certificate for the same key have the same identity`() {
        val key = randomECSigningKey(Curve.P_256)
        val certificate = selfSigned(key.toKeyPair())

        assertEquals(
            JwtBindingKey.Jwk(key.toPublicJWK()).batchIdentity(),
            JwtBindingKey.X509(listOf(certificate)).batchIdentity(),
        )
    }

    @Test
    fun `JWKs for the same key with different metadata have the same identity`() {
        val key = randomECSigningKey(Curve.P_256).toPublicJWK()
        val otherKid = JWK.parse(key.toJSONObject().apply { put("kid", "another-kid") })

        assertEquals(JwtBindingKey.Jwk(key).batchIdentity(), JwtBindingKey.Jwk(otherKid).batchIdentity())
    }

    @Test
    fun `different keys have different identities`() {
        val one = randomECSigningKey(Curve.P_256)
        val other = randomECSigningKey(Curve.P_256)

        assertNotEquals(
            JwtBindingKey.X509(listOf(selfSigned(one.toKeyPair()))).batchIdentity(),
            JwtBindingKey.X509(listOf(selfSigned(other.toKeyPair()))).batchIdentity(),
        )
        assertNotEquals(
            JwtBindingKey.Jwk(one.toPublicJWK()).batchIdentity(),
            JwtBindingKey.X509(listOf(selfSigned(other.toKeyPair()))).batchIdentity(),
        )
    }

    @Test
    fun `a certificate key that cannot be expressed as a JWK is compared by content`() {
        val certificate = selfSigned(KeyPairGenerator.getInstance("Ed25519").genKeyPair(), sigAlg = "Ed25519")
        assertTrue(runCatching { JWK.parse(certificate) }.isFailure, "this test needs a key that JWK.parse rejects")
        val copy = certificate.copy()

        assertEquals(
            JwtBindingKey.X509(listOf(certificate)).batchIdentity(),
            JwtBindingKey.X509(listOf(copy)).batchIdentity(),
        )
        assertNotEquals(
            JwtBindingKey.X509(listOf(certificate)).batchIdentity(),
            JwtBindingKey
                .X509(listOf(selfSigned(KeyPairGenerator.getInstance("Ed25519").genKeyPair(), sigAlg = "Ed25519")))
                .batchIdentity(),
        )
    }
}
