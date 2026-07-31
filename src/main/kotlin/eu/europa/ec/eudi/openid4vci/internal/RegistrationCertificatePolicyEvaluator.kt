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

import eu.europa.ec.eudi.openid4vci.AuthorizationPolicyValidationError.*
import eu.europa.ec.eudi.openid4vci.CredentialOffer
import eu.europa.ec.eudi.openid4vci.IssuerInfo
import eu.europa.ec.eudi.openid4vci.RegistrationCertificatePolicy
import kotlinx.serialization.json.JsonPrimitive

internal class RegistrationCertificatePolicyEvaluator(
    private val policy: RegistrationCertificatePolicy,
) {
    suspend fun evaluate(
        credentialOffer: CredentialOffer,
    ): RegistrationCertificatePolicy.Authorization {
        val metadata = credentialOffer.credentialIssuerMetadata

        val accessCertificate = ensureNotNull(metadata.metadataSigningCertificate) { MissingAccessCertificate() }

        val issuerInfoList = metadata.issuerInfo
        ensure(issuerInfoList != null && !issuerInfoList.isEmpty()) { MissingIssuerInfo() }

        val wrprc = issuerInfoList.registrationCertificate()

        val offeredCredentialConfigs = metadata.credentialConfigurationsSupported.filter {
            credentialOffer.credentialConfigurationIdentifiers.contains(it.key)
        }.values.toList()

        return policy.invoke(accessCertificate, wrprc, offeredCredentialConfigs)
    }

    private fun IssuerInfo.registrationCertificate(): String {
        val registrationCerts = attestations.filter {
            it.format == IssuerInfo.Attestation.Format.REGISTRATION_CERT
        }
        ensure(!registrationCerts.isEmpty()) { MissingRegistrationCertificate() }
        ensure(registrationCerts.size == 1) { MultipleRegistrationCertificates() }
        val attestation = registrationCerts.first()
        val dataValue = attestation.data.value
        ensure(dataValue is JsonPrimitive) {
            MalformedRegistrationCertificate("Provided registration certificate is not a JSON primitive")
        }
        return dataValue.content
    }
}
