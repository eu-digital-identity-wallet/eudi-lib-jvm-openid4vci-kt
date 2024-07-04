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

import eu.europa.ec.eudi.openid4vci.internal.http.NotificationEventTO
import eu.europa.ec.eudi.openid4vci.internal.http.NotificationTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.*

class IssuanceNotificationTest {

    @Test
    fun `when issuance response contains notification_id, it is present in and can be used for notifications`() = runTest {
        val credential = "issued_credential_content_sd_jwt_vc"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                credential = credential,
            ),
            RequestMocker(
                requestMatcher = endsWith("/notification", HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = "",
                        status = HttpStatusCode.NoContent,
                    )
                },
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
                    val notificationTO = Json.decodeFromString<NotificationTO>(textContent.text)
                    assertTrue("Not expected event type") {
                        notificationTO.event == NotificationEventTO.CREDENTIAL_ACCEPTED
                    }
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferWithSdJwtVc_NO_GRANTS,
        )
        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
                    val popSigner = CryptoGenerator.rsaProofSigner()
                    val (newAuthorizedRequest, outcome) =
                        authorizedRequest.requestSingleAndUpdateState(requestPayload, popSigner).getOrThrow()
                    assertIs<SubmissionOutcome.Success>(outcome, "Not a successful issuance")

                    val issuedCredential = outcome.credentials.firstOrNull()
                    assertIs<IssuedCredential.Issued>(issuedCredential, "Is Deferred although expecting Issued")
                    assertNotNull(issuedCredential.notificationId, "No notification id found")

                    newAuthorizedRequest.notify(
                        CredentialIssuanceEvent.Accepted(
                            id = issuedCredential.notificationId!!,
                            description = "Credential received and validated",
                        ),
                    )
                }
                else -> fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when notification request failed, a Result failure is returned`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            RequestMocker(
                requestMatcher = endsWith("/notification", HttpMethod.Post),
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "error": "invalid_notification_id"
                            }
                        """.trimIndent(),
                        status = HttpStatusCode.BadRequest,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferWithSdJwtVc_NO_GRANTS,
        )
        with(issuer) {
            val result = authorizedRequest.notify(
                CredentialIssuanceEvent.Accepted(
                    id = NotificationId("123456"),
                    description = "Credential received and validated",
                ),
            )

            result.fold(
                onSuccess = { fail("Expected failure but was not") },
                onFailure = {
                    assertIs<CredentialIssuanceError.NotificationFailed>(it)
                    assertTrue() {
                        it.error == "invalid_notification_id"
                    }
                },
            )
        }
    }
}
