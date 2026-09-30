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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.jwtProofWithKeyAttestationSpec
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import kotlin.test.*

/** The error codes of a Credential Error Response, OpenID4VCI 1.0 §8.3.1.2. */
class CredentialErrorCodeTest {

    private fun MockRequestHandleScope.credentialError(code: String) = respond(
        content = """{"error": "$code"}""",
        status = HttpStatusCode.BadRequest,
        headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
    )

    private suspend fun submit(credentialResponse: HttpResponseDataBuilder): Result<SubmissionOutcome> {
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
            httpClient = mockedHttpClient(
                credentialIssuerMetadataWellKnownMocker(),
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                singleIssuanceRequestMocker(responseBuilder = credentialResponse),
            ),
        )
        return with(issuer) {
            val payload = IssuanceRequestPayload.ConfigurationBased(issuer.credentialOffer.credentialConfigurationIdentifiers[0])
            authorizedRequest.request(payload, jwtProofWithKeyAttestationSpec(Curve.P_256)).map { it.second }
        }
    }

    @Test
    fun `unknown_credential_configuration is reported as UnknownCredentialConfiguration`() = runTest {
        val outcome = submit { credentialError("unknown_credential_configuration") }.getOrThrow()
        assertIs<SubmissionOutcome.Failed>(outcome)
        assertIs<CredentialIssuanceError.UnknownCredentialConfiguration>(outcome.error, "was ${outcome.error}")
    }

    @Test
    fun `unknown_credential_identifier is reported as UnknownCredentialIdentifier`() = runTest {
        val outcome = submit { credentialError("unknown_credential_identifier") }.getOrThrow()
        assertIs<SubmissionOutcome.Failed>(outcome)
        assertIs<CredentialIssuanceError.UnknownCredentialIdentifier>(outcome.error, "was ${outcome.error}")
    }

    @Test
    fun `invalid_encryption_parameters is reported as InvalidEncryptionParameters`() = runTest {
        val outcome = submit { credentialError("invalid_encryption_parameters") }.getOrThrow()
        assertIs<SubmissionOutcome.Failed>(outcome)
        assertIs<CredentialIssuanceError.InvalidEncryptionParameters>(outcome.error, "was ${outcome.error}")
    }
}
