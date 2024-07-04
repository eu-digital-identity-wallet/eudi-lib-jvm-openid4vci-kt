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

import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import kotlin.test.*

class IssuanceSingleRequestTest {

    @Test
    fun `when issuance requested with no proof then InvalidProof error is raised with c_nonce passed`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "error": "invalid_proof",
                                "c_nonce": "ERE%@^TGWYEYWEY",
                                "c_nonce_expires_in": 34
                            } 
                        """.trimIndent(),
                        status = HttpStatusCode.BadRequest,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
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
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertThat(
                        "Wrong credential request type",
                        issuanceRequestTO.format != null && issuanceRequestTO.format == FORMAT_MSO_MDOC,
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferMsoMdoc_NO_GRANTS,
        )

        val claimSet = MsoMdocClaimSet(
            claims = listOf(
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "family_name",
                "org.iso.18013.5.1" to "birth_date",
            ),

        )
        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val submittedRequest = assertDoesNotThrow {
                        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                    assertIs<SubmissionOutcome.InvalidProof>(submittedRequest)
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `when issuer responds with 'invalid_proof' and no c_nonce then ResponseUnparsable error is returned `() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    respond(
                        content = """
                            {
                                "error": "invalid_proof"                               
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
            CredentialOfferMsoMdoc_NO_GRANTS,
        )

        val claimSet = MsoMdocClaimSet(
            claims = listOf(
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "family_name",
                "org.iso.18013.5.1" to "birth_date",
            ),
        )
        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val request = assertDoesNotThrow {
                        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                    assertIs<SubmissionOutcome.Failed>(request)
                    assertIs<CredentialIssuanceError.ResponseUnparsable>(request.error)
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `when issuance request contains unsupported claims exception CredentialIssuanceException is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val claimSetMsoMdoc = MsoMdocClaimSet(listOf("org.iso.18013.5.1" to "degree"))
                    var credentialConfigurationId = CredentialConfigurationIdentifier(PID_MsoMdoc)
                    assertFailsWith<CredentialIssuanceError.InvalidIssuanceRequest> {
                        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSetMsoMdoc)
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }

                    val claimSetSdJwtVc = GenericClaimSet(listOf("degree"))
                    credentialConfigurationId = CredentialConfigurationIdentifier(PID_SdJwtVC)
                    assertFailsWith<CredentialIssuanceError.InvalidIssuanceRequest> {
                        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSetSdJwtVc)
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `when issuer used to request credential not included in offer an IllegalArgumentException is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = CredentialConfigurationIdentifier("UniversityDegree")
                    assertFailsWith<IllegalArgumentException> {
                        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `successful issuance of credential in mso_mdoc format`() = runTest {
        val credential = "issued_credential_content_mso_mdoc"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                credential = credential,
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    issuanceRequest.proof?.let {
                        assertIs<Proof.Jwt>(issuanceRequest.proof)
                    }
                    assertThat(
                        "Expected mso_mdoc format based issuance request but was not.",
                        issuanceRequest.format != null && issuanceRequest.format == FORMAT_MSO_MDOC,
                    )
                },
            ),
        )

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferMsoMdoc_NO_GRANTS,
        )

        val claimSet = MsoMdocClaimSet(
            claims = listOf(
                "org.iso.18013.5.1" to "given_name",
                "org.iso.18013.5.1" to "family_name",
                "org.iso.18013.5.1" to "birth_date",
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                    val popSigner = CryptoGenerator.rsaProofSigner()
                    val (newAuthorized, outcome) = authorizedRequest.requestSingleAndUpdateState(requestPayload, popSigner).getOrThrow()
                    assertIs<SubmissionOutcome.Success>(outcome)
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `successful issuance of credential in vc+sd-jwt format`() = runBlocking {
        val credential = "issued_credential_content_sd_jwt_vc"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                credential = credential,
            ),
        )

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferWithSdJwtVc_NO_GRANTS,
        )

        val claimSet = GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "birth_date",
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                    val popSigner = CryptoGenerator.rsaProofSigner()
                    val (newAuthorizedRequest, outcome) = authorizedRequest.requestSingleAndUpdateState(
                        requestPayload,
                        popSigner,
                    ).getOrThrow()
                    assertTrue { authorizedRequest != newAuthorizedRequest }
                    assertIs<SubmissionOutcome.Success>(outcome)
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
        Unit
    }

    @Test
    fun `successful issuance of credential in jwt_vc_json format`() = runTest {
        val credential = "issued_credential_content_jwt_vc_json"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                credential = credential,
            ),
        )

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferWithJwtVcJson_NO_GRANTS,
        )

        val claimSet = GenericClaimSet(
            claims = listOf(
                "given_name",
                "family_name",
                "degree",
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                    val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                    val (newAuthorizedRequest, outcome) = authorizedRequest.requestSingleAndUpdateState(
                        requestPayload,
                        CryptoGenerator.rsaProofSigner(),
                    ).getOrThrow()
                    assertTrue { authorizedRequest != newAuthorizedRequest }
                    assertIs<SubmissionOutcome.Success>(outcome)
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when token endpoint returns credential identifiers, issuance request must be IdentifierBasedIssuanceRequestTO`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertThat(
                        "Expected identifier based issuance request but credential_identifier is null",
                        issuanceRequestTO.credentialIdentifier != null,
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val requestPayload = authorizedRequest.credentialIdentifiers?.let {
                        IssuanceRequestPayload.IdentifierBased(it.entries.first().key, it.entries.first().value[0])
                    } ?: error("No credential identifier")
                    authorizedRequest.requestSingle(requestPayload).getOrThrow()
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when request is by credential id, this id must be in the list of identifiers returned from token endpoint`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertThat(
                        "Expected identifier based issuance request but credential_identifier is null",
                        issuanceRequestTO.credentialResponseEncryption != null,
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val requestPayload = IssuanceRequestPayload.IdentifierBased(
                        CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                        CredentialIdentifier("DUMMY"),
                    )
                    assertThrows<IllegalArgumentException> {
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `issuance request by credential id, is allowed only when token endpoint has returned credential identifiers`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertThat(
                        "Expected identifier based issuance request but credential_identifier is null",
                        issuanceRequestTO.credentialIdentifier != null,
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val requestPayload = IssuanceRequestPayload.IdentifierBased(
                        CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
                        CredentialIdentifier("id"),
                    )
                    assertThrows<IllegalArgumentException> {
                        authorizedRequest.requestSingle(requestPayload).getOrThrow()
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when token endpoint returns authorization_details they are parsed properly`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertThat(
                        "Expected identifier based issuance request but credential_identifier is null",
                        issuanceRequestTO.credentialIdentifier != null,
                    )
                },
            ),
        )
        val (authorizedRequest, _) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CREDENTIAL_OFFER_NO_GRANTS,
        )

        assertTrue("Identifiers expected to be parsed") {
            !authorizedRequest.credentialIdentifiers.isNullOrEmpty()
        }
    }
}
