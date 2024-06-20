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

import eu.europa.ec.eudi.openid4vci.internal.http.DeferredRequestTO
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.*

class IssuanceDeferredRequestTest {

    @Test
    fun `when issuer responds with invalid_transaction_id, response should be of type Errored`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(credentialIsReady = true, transactionIdIsValid = false) },
            ),
        )
        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                CredentialOfferWithSdJwtVc_NO_GRANTS,
            )

        with(issuer) {
            assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)

            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
                null,
            )
            val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()
            assertIs<SubmissionOutcome.InvalidProof>(submittedRequest)

            val proofRequired = authorizedRequest.withCNonce(submittedRequest.cNonce)
            val secondSubmittedRequest =
                proofRequired.requestSingle(requestPayload, CryptoGenerator.rsaProofSigner()).getOrThrow()

            assertIs<SubmissionOutcome.Success>(secondSubmittedRequest)

            val issuedCredential = secondSubmittedRequest.credentials[0]
            assertIs<IssuedCredential.Deferred>(issuedCredential)

            val requestDeferredIssuance =
                authorizedRequest.queryForDeferredCredential(issuedCredential)
                    .getOrThrow()

            assertIs<DeferredCredentialQueryOutcome.Errored>(requestDeferredIssuance)
            assertTrue("Expected error response invalid_transaction_id but was not") {
                requestDeferredIssuance.error != "invalid_transaction_id"
            }
        }
    }

    @Test
    fun `when issuer responds with issuance_pending, response should be of type IssuancePending`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = { respondToIssuanceRequestWithDeferredResponseDataBuilder(it) },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = { defaultIssuanceResponseDataBuilder(false) },
            ),
        )

        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                CredentialOfferWithSdJwtVc_NO_GRANTS,
            )

        with(issuer) {
            assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
                null,
            )
            val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()

            assertIs<SubmissionOutcome.InvalidProof>(submittedRequest)
            val proofRequired = authorizedRequest.withCNonce(submittedRequest.cNonce)
            val secondSubmittedRequest =
                proofRequired.requestSingle(requestPayload, CryptoGenerator.rsaProofSigner()).getOrThrow()

            assertIs<SubmissionOutcome.Success>(secondSubmittedRequest)
            val issuedCredential = secondSubmittedRequest.credentials[0]
            assertIs<IssuedCredential.Deferred>(issuedCredential)

            val requestDeferredIssuance =
                authorizedRequest.queryForDeferredCredential(issuedCredential)
                    .getOrThrow()

            assertIs<DeferredCredentialQueryOutcome.IssuancePending>(requestDeferredIssuance)
            assertTrue("Expected interval but was not present") {
                requestDeferredIssuance.interval != null
            }
        }
    }

    @Test
    fun `when deferred request is valid, credential must be issued`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
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

        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                CredentialOfferWithSdJwtVc_NO_GRANTS,
            )

        with(issuer) {
            assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
                null,
            )
            val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()

            assertIs<SubmissionOutcome.InvalidProof>(submittedRequest)
            val proofRequired = authorizedRequest.withCNonce(submittedRequest.cNonce)
            val secondSubmittedRequest =
                proofRequired.requestSingle(requestPayload, CryptoGenerator.rsaProofSigner()).getOrThrow()

            assertIs<SubmissionOutcome.Success>(secondSubmittedRequest)
            val issuedCredential = secondSubmittedRequest.credentials[0]
            require(issuedCredential is IssuedCredential.Deferred)

            val requestDeferredIssuance = authorizedRequest.queryForDeferredCredential(issuedCredential)
                .getOrThrow()
            assertIs<DeferredCredentialQueryOutcome.Issued>(requestDeferredIssuance)
        }
    }

    private fun asDeferredIssuanceRequest(bodyStr: String): DeferredRequestTO? =
        try {
            Json.decodeFromString<DeferredRequestTO>(bodyStr)
        } catch (ex: Exception) {
            null
        }
}
