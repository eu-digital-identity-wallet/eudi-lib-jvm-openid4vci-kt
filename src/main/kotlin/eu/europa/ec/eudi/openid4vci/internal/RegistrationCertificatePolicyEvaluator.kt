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

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.IssuanceAuthorizationError.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.cert.X509Certificate

sealed class IssuanceAuthorizationError(cause: Throwable) : Throwable(cause) {

    class MissingIssuerInfo :
        IssuanceAuthorizationError(IllegalArgumentException("Missing issuer info"))

    class MissingRegistrationCertificate :
        IssuanceAuthorizationError(IllegalArgumentException("Missing issuer registration certificate"))

    class MultipleRegistrationCertificates :
        IssuanceAuthorizationError(IllegalArgumentException("Multiple Registration Certificates provided while only one expected"))

    class RegistrationCertificateNotTrusted :
        IssuanceAuthorizationError(IllegalArgumentException("Registration certificate not trusted"))

    class MissingAccessCertificate :
        IssuanceAuthorizationError(IllegalArgumentException("Missing access certificate"))

    class AuthorizationPolicyNotMet(val violation: RegistrationCertificatePolicy.PolicyViolation) :
        IssuanceAuthorizationError(IllegalArgumentException("Authorization policy not met"))

    class MalformedRegistrationCertificate(msg: String) :
        IssuanceAuthorizationError(IllegalArgumentException(msg)) {
            init {
                require(msg.isNotEmpty()) { "Cause cannot be empty" }
            }
        }
}

internal class RegistrationCertificatePolicyEvaluator(
    private val policy: RegistrationCertificatePolicy,
) {

    suspend fun evaluate(
        credentialOffer: CredentialOffer,
    ): RegistrationCertificatePolicy.Authorization {
        val metadata = credentialOffer.credentialIssuerMetadata

        val issuerInfoList = metadata.issuerInfo
        ensure(issuerInfoList != null && !issuerInfoList.isEmpty()) { MissingIssuerInfo() }

        val registrationCerts = issuerInfoList.attestations
            .filter { it.format == IssuerInfo.Attestation.Format.REGISTRATION_CERT }

        ensure(!registrationCerts.isEmpty()) { MissingRegistrationCertificate() }
        ensure(registrationCerts.size == 1) { MultipleRegistrationCertificates() }

        val attestation = registrationCerts.first()
        val dataValue = attestation.data.value
        ensure(dataValue is JsonPrimitive) { MalformedRegistrationCertificate("data field must be a string") }

        val wrprc = try {
            SignedJWT.parse(dataValue.content)
        } catch (e: Exception) {
            throw MalformedRegistrationCertificate("Failed to parse WRPRC JWT: ${e.message}")
        }

        val trustedX509CertChain = wrprc.trustedX509CertChain(policy.trust)
        wrprc.verifyTrustedSignature(trustedX509CertChain)

        val accessCertificate = ensureNotNull(metadata.accessCertificate) { MissingAccessCertificate() }

        val offeredCredentialConfigs = metadata.credentialConfigurationsSupported.filter {
            credentialOffer.credentialConfigurationIdentifiers.contains(it.key)
        }.values.toList()

        val wrprcClaimset = wrprc.jwtClaimsSet.toJSONObject().toKotlinxJsonObject()
        return policy.apply(accessCertificate, wrprcClaimset, offeredCredentialConfigs)
    }

    private fun Map<String, Any?>.toKotlinxJsonObject(): JsonObject {
        val jsonString = JSONObjectUtils.toJSONString(this)
        return Json.decodeFromString(jsonString)
    }

    private suspend fun SignedJWT.trustedX509CertChain(issuerTrust: IssuerTrust): List<X509Certificate> {
        val x5c = header?.x509CertChain
        ensureNotNull(x5c) { MalformedRegistrationCertificate("Missing x5c header") }
        val pubCertChain = x5c.mapNotNull { runCatchingCancellable { X509CertUtils.parse(it.decode()) }.getOrNull() }
        ensure(pubCertChain.isNotEmpty()) { MalformedRegistrationCertificate("Invalid x5c") }
        ensure(issuerTrust.certificateChainTrust.isTrusted(pubCertChain)) { RegistrationCertificateNotTrusted() }

        val leafCert = pubCertChain.first()
        val jwk = JWK.parse(leafCert)
        ensure(jwk is AsymmetricJWK) {
            MalformedRegistrationCertificate("WRPRC signing key must be asymmetric")
        }

        return pubCertChain
    }

    private fun SignedJWT.verifyTrustedSignature(certCain: List<X509Certificate>) {
        try {
            val processor = DefaultJWTProcessor<SecurityContext>()
                .apply {
                    jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(ETSI119475.REG_CERT_HEADER_TYPE))
                    jwsKeySelector = JWSKeySelector { _, _ -> listOf(certCain.first().publicKey) }
                }
            processor.process(this, null)
        } catch (e: JOSEException) {
            throw MalformedRegistrationCertificate("Could not verify signature of registration certificate: ${e.message}")
        } catch (e: BadJOSEException) {
            throw MalformedRegistrationCertificate("Registration certificate invalid signature: ${e.message}")
        }
    }
}
