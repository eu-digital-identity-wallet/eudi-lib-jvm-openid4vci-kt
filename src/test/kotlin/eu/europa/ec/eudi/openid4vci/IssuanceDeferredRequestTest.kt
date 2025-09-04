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
package eu.europa.ec.eudi.openid4vci

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.proofsSpecForEcKeys
import eu.europa.ec.eudi.openid4vci.internal.http.DeferredRequestTO
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class IssuanceDeferredRequestTest {

    @Test
    fun `when issuer responds with invalid_transaction_id, response should be of type Errored`() = runTest {
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(credentialIsReady = true, transactionIdIsValid = false) },
            ),
        )
        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
            )
            val (newAuthorizedRequest, outcome) =
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256)).getOrThrow()
            assertIs<SubmissionOutcome.Deferred>(outcome)

            val (_, requestDeferredIssuance) =
                newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId)
                    .getOrThrow()

            assertIs<DeferredCredentialQueryOutcome.Errored>(requestDeferredIssuance)
            assertTrue("Expected error response invalid_transaction_id but was not") {
                requestDeferredIssuance.error == "invalid_transaction_id"
            }
        }
    }

    @Test
    fun `when issuer needs more time to prepare credential, issuance outcome is IssuancePending`() = runTest {
        val transactionId = TransactionId(UUID.randomUUID().toString())
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it, transactionId) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(false, transactionId) },
            ),
        )

        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
            )
            val (newAuthorizedRequest, outcome) =
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256)).getOrThrow()
            assertIs<SubmissionOutcome.Deferred>(outcome)

            val (_, requestDeferredIssuance) =
                newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId)
                    .getOrThrow()

            val issuancePending = assertIs<DeferredCredentialQueryOutcome.IssuancePending>(requestDeferredIssuance)
            assertEquals(transactionId, issuancePending.transactionId)
        }
    }

    @Test
    fun `when issuer needs more time to prepare credential and responds with unexpected transaction id, request fails`() = runTest {
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(false) },
            ),
        )

        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
            )
            val (newAuthorizedRequest, outcome) =
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256)).getOrThrow()
            assertIs<SubmissionOutcome.Deferred>(outcome)

            assertFailsWith<CredentialIssuanceError.UnexpectedTransactionId> {
                newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId).getOrThrow()
            }
        }
    }

    @Test
    fun `when deferred request is valid, credential must be issued`() = runTest {
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(true) },
                requestValidator = {
                    assertTrue("No Authorization header passed.") {
                        it.headers.contains("Authorization")
                    }

                    assertTrue("Authorization header malformed.") {
                        it.headers["Authorization"]?.contains("Bearer") ?: false
                    }
                    assertTrue("Content Type must be application/json") {
                        it.body.contentType == ContentType.parse("application/json")
                    }
                    val textContent = it.body as TextContent
                    val deferredIssuanceRequest = asDeferredIssuanceRequest(textContent.text)
                    deferredIssuanceRequest?.let {
                        assertTrue("No transaction id passed") {
                            deferredIssuanceRequest.transactionId.isNotBlank()
                        }
                    }
                },
            ),
        )

        val (authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
            )
            val (newAuthorized, outcome) =
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256)).getOrThrow()

            assertIs<SubmissionOutcome.Deferred>(outcome)

            val (_, requestDeferredIssuance) = newAuthorized.queryForDeferredCredential(outcome.transactionId).getOrThrow()
            assertIs<DeferredCredentialQueryOutcome.Issued>(requestDeferredIssuance)
        }
    }

    private fun asDeferredIssuanceRequest(bodyStr: String): DeferredRequestTO? =
        try {
            Json.decodeFromString<DeferredRequestTO>(bodyStr)
        } catch (_: Exception) {
            null
        }
}
