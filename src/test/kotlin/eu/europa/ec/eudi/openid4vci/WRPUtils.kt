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
@file:OptIn(ExperimentalTime::class)

package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.CertOps.toX509Certificate
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import kotlinx.serialization.json.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

private const val SIGN_ALG = "SHA256withECDSA"
private const val ETSI119475_REG_CERT_HEADER_TYPE = "rc-wrp+jwt"

internal data class CertificateAndKey(
    val keyPair: KeyPair,
    val cert: X509CertificateHolder,
) {
    companion object {
        operator fun invoke(certAndKey: Pair<KeyPair, X509CertificateHolder>): CertificateAndKey =
            CertificateAndKey(certAndKey.first, certAndKey.second)
    }
}

internal data class RootCa(val certAndKey: CertificateAndKey) {

    companion object {

        val NAME: X500Name = X500Name("CN=RootCa")

        val DEFAULT = RootCa(CertOps.genTrustAnchor(SIGN_ALG, NAME))

        operator fun invoke(certAndKey: Pair<KeyPair, X509CertificateHolder>): RootCa =
            RootCa(CertificateAndKey(certAndKey))
    }
}

internal class WrpacProvider(private val certAndKey: CertificateAndKey) {

    fun issueAccessCertificate(subjectName: X500Name): Pair<KeyPair, List<X509Certificate>> {
        val (keyPair, wrpac) = CertOps.genEndEntity(
            signerCert = certAndKey.cert,
            signerKey = certAndKey.keyPair.private,
            sigAlg = SIGN_ALG,
            subject = subjectName,
        )
        return keyPair to listOf(
            wrpac.toX509Certificate(),
            certAndKey.cert.toX509Certificate(),
        )
    }

    companion object {
        val NAME: X500Name = X500Name("CN=Wrpac Provider")

        operator fun invoke(certAndKey: Pair<KeyPair, X509CertificateHolder>): WrpacProvider =
            WrpacProvider(CertificateAndKey(certAndKey))
    }
}

internal class WrprcProvider(
    private val certAndKey: CertificateAndKey,
    private val clock: Clock,
) {

    fun issueWRPRC(wrprcContent: JsonObject): SignedJWT {
        val jwsHeader = header()
        val payload = payload(wrprcContent)
        val jWSObject = JWSObject(jwsHeader, payload).apply {
            sign(certAndKey.keyPair.jwsSigner(JWSAlgorithm.ES256))
        }
        return SignedJWT.parse(jWSObject.serialize())
    }

    private fun payload(wrprcContent: JsonObject): Payload = wrprcContent
        .buildUpon {
            put(RFC7519.ISSUED_AT, clock.now().epochSeconds)
        }.let {
            Payload(JSONObjectUtils.parse(Json.encodeToString(it)))
        }

    private fun header(): JWSHeader? = JWSHeader.Builder(JWSAlgorithm.ES256)
        .apply {
            type(JOSEObjectType(ETSI119475_REG_CERT_HEADER_TYPE))
            x509CertChain(
                listOf(Base64.encode(certAndKey.cert.encoded)),
            )
        }.build()

    companion object {
        val NAME: X500Name = X500Name("CN=Wrprc Provider")

        operator fun invoke(
            certAndKey: Pair<KeyPair, X509CertificateHolder>,
            clock: Clock,
        ): WrprcProvider = WrprcProvider(CertificateAndKey(certAndKey), clock)
    }
}

internal class Registrar(
    private val clock: Clock,
    private val wrpacProvider: WrpacProvider,
    private val wrprcProvider: WrprcProvider,
) {

    fun registerAttestationProvider(issuer: CredentialIssuerId, wrprcContent: JsonObject): AttestationProvider {
        val name = X500Name("CN=${issuer.value.value.host}")
        val (wrpacKeyPair, wrpacCertChain) = wrpacProvider.issueAccessCertificate(name)
        val wrprc = wrprcProvider.issueWRPRC(wrprcContent)

        return AttestationProvider(
            id = issuer,
            clock = clock,
            wrpacKey = wrpacKeyPair,
            wrpacCertChain = wrpacCertChain,
            wrprc = wrprc,
        )
    }

    companion object {
        operator fun invoke(
            clock: Clock,
            rootCa: RootCa = RootCa.DEFAULT,
        ): Registrar {
            val wrpacCertAndKey = CertOps.genIntermediateCertificate(
                signerCert = rootCa.certAndKey.cert,
                signerKey = rootCa.certAndKey.keyPair.private,
                sigAlg = SIGN_ALG,
                subject = WrpacProvider.NAME,
            )

            val wrprcCertAndKey = CertOps.genIntermediateCertificate(
                signerCert = rootCa.certAndKey.cert,
                signerKey = rootCa.certAndKey.keyPair.private,
                sigAlg = SIGN_ALG,
                subject = WrprcProvider.NAME,
            )

            return Registrar(
                clock,
                WrpacProvider(wrpacCertAndKey),
                WrprcProvider(wrprcCertAndKey, clock),
            )
        }
    }
}

internal class AttestationProvider(
    val id: CredentialIssuerId,
    val wrprc: SignedJWT,
    val wrpacCertChain: List<X509Certificate>,
    private val clock: Clock,
    private val wrpacKey: KeyPair,
) {
    private val metadataJson = getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json")

    fun unsignedMetadata(): CredentialIssuerMetadata =
        CredentialIssuerMetadataJsonParser.parseMetaData(metadataJson, id)

    fun signedMetadata(): SignedJWT {
        val metadataJson = Json.decodeFromString<JsonObject>(metadataJson).embedWrprc()
        val jwsHeader = header()
        val payload = metadataJson.toPayload()
        val jWSObject = JWSObject(jwsHeader, payload)
            .apply {
                sign(wrpacKey.jwsSigner(JWSAlgorithm.ES256))
            }
        return SignedJWT.parse(jWSObject.serialize())
    }

    private fun JsonObject.toPayload(): Payload = this
        .buildUpon {
            put(RFC7519.ISSUED_AT, clock.now().epochSeconds)
            put(RFC7519.ISSUER, id.toString())
            put(RFC7519.SUBJECT, id.toString())
        }.let {
            Payload(JSONObjectUtils.parse(Json.encodeToString(it)))
        }

    private fun header(): JWSHeader? = JWSHeader.Builder(JWSAlgorithm.ES256)
        .apply {
            type(JOSEObjectType(OpenId4VCISpec.SIGNED_METADATA_JWT_TYPE))
            x509CertChain(wrpacCertChain.map { Base64.encode(it.encoded) })
        }.build()

    private fun JsonObject.embedWrprc(): JsonObject = this
        .buildUpon {
            put(
                "issuer_info",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put(ETSI119472Part3.FORMAT, ETSI119472Part3.REGISTRATION_CERT)
                            put(ETSI119472Part3.DATA, wrprc.serialize())
                        },
                    )
                },
            )
        }
}

private fun Map<String, JsonElement>.buildUpon(builder: JsonObjectBuilder.() -> Unit): JsonObject =
    buildJsonObject {
        entries.forEach { (key, value) -> put(key, value) }
        builder()
    }

private fun KeyPair.jwsSigner(signingAlg: JWSAlgorithm): JWSSigner =
    if (JWSAlgorithm.Family.RSA.contains(signingAlg)) {
        RSASSASigner(private)
    } else if (JWSAlgorithm.Family.EC.contains(signingAlg)) {
        val publicKey = public as ECPublicKey
        val privateKey = private as ECPrivateKey
        val ecKey = ECKey.Builder(signingAlg.curve(), publicKey).privateKey(privateKey).build()
        ECDSASigner(ecKey)
    } else {
        error("Unsupported alg $signingAlg")
    }

private fun JWSAlgorithm.curve(): Curve = when (this) {
    JWSAlgorithm.ES256 -> Curve.P_256
    JWSAlgorithm.ES384 -> Curve.P_384
    JWSAlgorithm.ES512 -> Curve.P_521
    else -> error("Unsupported EC alg $this")
}
