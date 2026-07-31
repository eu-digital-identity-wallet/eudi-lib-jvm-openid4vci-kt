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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.IssuerInfo.Attestation
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.ExperimentalTime

class RegistrationCertificatePolicyEvaluatorTest {

    val pidProviderId = CredentialIssuerId(CREDENTIAL_ISSUER_PUBLIC_URL).getOrThrow()

    @OptIn(ExperimentalTime::class)
    private val pidProvider = Registrar(Clock.System).registerAttestationProvider(pidProviderId, buildJsonObject { })

    @Test
    fun `evaluate throws MissingAccessCertificate when no AccessCertificate present in issuer metadata`() = runTest {
        val evaluator = RegistrationCertificatePolicyEvaluator { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }

        val unsignedMetadata = pidProvider.unsignedMetadata()
        val credentialOffer = credentialOffer(unsignedMetadata)

        assertFailsWith<AuthorizationPolicyValidationError.MissingAccessCertificate> {
            evaluator.evaluate(credentialOffer)
        }
    }

    @Test
    fun `evaluate throws MissingIssuerInfo when issuerInfo is not present`() = runTest {
        val evaluator = RegistrationCertificatePolicyEvaluator { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }

        val metadata = pidProvider.signedMetadata().toDomain()
        val metadataNoIssuerInfo = metadata.copy(issuerInfo = null)

        val credentialOffer = credentialOffer(metadataNoIssuerInfo)

        assertFailsWith<AuthorizationPolicyValidationError.MissingIssuerInfo> {
            evaluator.evaluate(credentialOffer)
        }
    }

    @Test
    fun `evaluate throws MissingRegistrationCertificate when issuerInfo does not include required registration certificate`() = runTest {
        val evaluator = RegistrationCertificatePolicyEvaluator { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }

        val metadata = pidProvider.signedMetadata().toDomain()
        val metadataNoWrprc = metadata.copy(
            issuerInfo = IssuerInfo(
                listOf(
                    Attestation(
                        format = Attestation.Format("wrprc"),
                        data = Attestation.Data(JsonPrimitive("wrprc_data")),
                    ),
                ),
            ),
        )

        val credentialOffer = credentialOffer(metadataNoWrprc)

        assertFailsWith<AuthorizationPolicyValidationError.MissingRegistrationCertificate> {
            evaluator.evaluate(credentialOffer)
        }
    }

    @Test
    fun `evaluate throws MultipleRegistrationCertificates when includes multiple registration certificates`() = runTest {
        val evaluator = RegistrationCertificatePolicyEvaluator { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }

        val metadata = pidProvider.signedMetadata().toDomain()
        val metadataMultipleRegCert = metadata.copy(
            issuerInfo = IssuerInfo(
                listOf(
                    Attestation(
                        format = Attestation.Format.REGISTRATION_CERT,
                        data = Attestation.Data(JsonPrimitive("wrprc_data")),
                    ),
                    Attestation(
                        format = Attestation.Format.REGISTRATION_CERT,
                        data = Attestation.Data(JsonPrimitive("wrprc_data")),
                    ),
                ),
            ),
        )

        val credentialOffer = credentialOffer(metadataMultipleRegCert)

        assertFailsWith<AuthorizationPolicyValidationError.MultipleRegistrationCertificates> {
            evaluator.evaluate(credentialOffer)
        }
    }

    @Test
    fun `evaluate throws MalformedRegistrationCertificate when registration certificate is not a json string`() = runTest {
        val evaluator = RegistrationCertificatePolicyEvaluator { _, _, _ -> RegistrationCertificatePolicy.Authorization.Granted() }

        val metadata = pidProvider.signedMetadata().toDomain()
        val metadataMalformedWrprc = metadata.copy(
            issuerInfo = IssuerInfo(
                listOf(
                    Attestation(
                        format = Attestation.Format.REGISTRATION_CERT,
                        data = Attestation.Data(
                            buildJsonObject {
                                put("key", "value")
                            },
                        ),
                    ),
                ),
            ),
        )

        val credentialOffer = credentialOffer(metadataMalformedWrprc)

        assertFailsWith<AuthorizationPolicyValidationError.MalformedRegistrationCertificate> {
            evaluator.evaluate(credentialOffer)
        }
    }

    private fun SignedJWT.toDomain(): CredentialIssuerMetadata {
        val (metadataJson, accessCertificate) = parseAndVerifySignedMetadata(this, pidProvider.id).getOrThrow()
        val metadata = CredentialIssuerMetadataJsonParser.parseMetaData(metadataJson, pidProvider.id)
        return metadata.copy(metadataSigningCertificate = accessCertificate)
    }

    private fun parseAndVerifySignedMetadata(
        signedJwt: SignedJWT,
        issuer: CredentialIssuerId,
    ): Result<Pair<String, X509Certificate?>> = runCatchingCancellable {
        val processor = DefaultJWTProcessor<SecurityContext>()
            .apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(OpenId4VCISpec.SIGNED_METADATA_JWT_TYPE))
                jwsKeySelector = keySelector(signedJwt)
                jwtClaimsSetVerifier =
                    DefaultJWTClaimsVerifier(
                        null,
                        JWTClaimsSet.Builder()
                            .subject(issuer.value.value.toExternalForm())
                            .build(),
                        setOf("iat", "sub"),
                    )
            }

        val claimsSet = processor.process(signedJwt, null)
        val metadataJson = JSONObjectUtils.toJSONString(claimsSet.toJSONObject())
        val leafCertificate = signedJwt.header.x509CertChain?.let { certChain ->
            X509CertChainUtils.parse(certChain).firstOrNull()
        }
        metadataJson to leafCertificate
    }

    private fun keySelector(signedJwt: SignedJWT): JWSKeySelector<SecurityContext> {
        val certChain = requireNotNull(signedJwt.header.x509CertChain) {
            "missing 'x5c' header claim"
        }.let { X509CertChainUtils.parse(it) }

        val jwk = JWK.parse(certChain.first())

        require(jwk is AsymmetricJWK) {
            "Metadata signing key should be asymmetric."
        }

        val algorithm = signedJwt.header.algorithm
        return SingleKeyJWSKeySelector(algorithm, jwk.toPublicKey())
    }
}
