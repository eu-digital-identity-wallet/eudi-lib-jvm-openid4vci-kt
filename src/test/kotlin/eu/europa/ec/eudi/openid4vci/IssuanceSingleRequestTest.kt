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
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseUnparsable
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.proofsSpecForEcKeys
import eu.europa.ec.eudi.openid4vci.IssuerMetadataVersion.NO_NONCE_ENDPOINT
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.serialization.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import kotlin.test.*

class IssuanceSingleRequestTest {

    @Test
    fun `when issuer responds with invalid_proof it is reflected in the submission outcomes`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
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
                    assertTrue(
                        issuanceRequestTO.credentialConfigurationId != null,
                        "Expected request by configuration id but was not.",
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        with(issuer) {
            val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
            val (_, outcome) = assertDoesNotThrow {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 3)).getOrThrow()
            }
            assertIs<SubmissionOutcome.Failed>(outcome)
            assertIs<CredentialIssuanceError.InvalidProof>(outcome.error)
        }
    }

    @Test
    fun `when the requested credential is not included in the offer an IllegalArgumentException is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val credentialConfigurationId = CredentialConfigurationIdentifier("UniversityDegree")
        assertFailsWith<IllegalStateException> {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
            with(issuer) {
                authorizedRequest.request(requestPayload, ProofsSpecification.NoProofs).getOrThrow()
            }
        }
    }

    @Test
    fun `when the passed PoPSigners are more than the expected batch limit IssuerBatchSizeLimitExceeded is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
        assertFailsWith<CredentialIssuanceError.IssuerBatchSizeLimitExceeded> {
            with(issuer) {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 4)).getOrThrow()
            }
        }
    }

    @Test
    fun `when credential configuration config does not demand proofs, no proof is included in the request`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNull(
                        issuanceRequest.proof,
                        "No proof expected to be sent with request but was sent.",
                    )
                },
            ),
        )

        // In issuer metadata the 'MobileDrivingLicense_msoMdoc' credential is configured to demand no proofs
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferWithMDLMdoc_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
            authorizedRequest.request(requestPayload, ProofsSpecification.NoProofs).getOrThrow()
        }
    }

    @Test
    fun `when credential configuration config demands proofs and issuer has no nonce endpoint, expect proofs without nonce`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(NO_NONCE_ENDPOINT),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequest.proof,
                        "Proof expected to be sent but was not sent.",
                    )
                    assertIs<Proof.Jwt>(issuanceRequest.proof)
                    val cNonce = issuanceRequest.proof.jwt.jwtClaimsSet.getStringClaim("nonce")
                    assertNull(
                        cNonce,
                        "No c_nonce expected in proof but found one",
                    )
                },
            ),
        )

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
            authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 1)).getOrThrow()
        }
    }

    @Test
    fun `successful issuance of credential requested by credential configuration id`() = runTest {
        val credential = "issued_credential_content_mso_mdoc"
        val nonceValue = "c_nonce_from_endpoint"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(nonceValue),
            singleIssuanceRequestMocker(
                credential = credential,
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertTrue(
                        issuanceRequest.credentialConfigurationId != null,
                        "Expected request by configuration id but was not.",
                    )
                    assertNotNull(
                        issuanceRequest.proof,
                        "Proof expected to be sent but was not sent.",
                    )
                    assertIs<Proof.Jwt>(issuanceRequest.proof)
                    val cNonce = issuanceRequest.proof.jwt.jwtClaimsSet.getStringClaim("nonce")
                    assertNotNull(
                        cNonce,
                        "c_nonce expected to be found in proof but was not",
                    )
                    assertEquals(
                        cNonce,
                        nonceValue,
                        "Expected c_nonce $nonceValue but found $cNonce",
                    )
                },
            ),
        )

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
        val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
        val (_, outcome) = with(issuer) {
            authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 1)).getOrThrow()
        }
        assertIs<SubmissionOutcome.Success>(outcome)
    }

    @Test
    fun `when token endpoint returns credential identifiers, issuance request must be IdentifierBasedIssuanceRequestTO`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            nonceEndpointMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequestTO.credentialIdentifier,
                        "Expected identifier based issuance request but credential_identifier is null",
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val requestPayload = authorizedRequest.credentialIdentifiers?.let {
            IssuanceRequestPayload.IdentifierBased(
                it.entries.first().key,
                it.entries.first().value[0],
            )
        } ?: error("No credential identifier")
        with(issuer) {
            authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 1)).getOrThrow()
        }
    }

    @Test
    fun `when request is by credential id, this id must be in the list of identifiers returned from token endpoint`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            nonceEndpointMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequestTO.credentialResponseEncryption,
                        "Expected identifier based issuance request but credential_identifier is null",
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val requestPayload = IssuanceRequestPayload.IdentifierBased(
            CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
            CredentialIdentifier("DUMMY"),
        )
        assertThrows<IllegalStateException> {
            with(issuer) {
                authorizedRequest.request(requestPayload, ProofsSpecification.NoProofs).getOrThrow()
            }
        }
    }

    @Test
    fun `issuance request by credential id, is allowed only when token endpoint has returned credential identifiers`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequestTO.credentialIdentifier,
                        "Expected identifier based issuance request but credential_identifier is null",

                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        val requestPayload = IssuanceRequestPayload.IdentifierBased(
            CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt"),
            CredentialIdentifier("id"),
        )
        assertThrows<IllegalStateException> {
            with(issuer) {
                authorizedRequest.request(requestPayload, ProofsSpecification.NoProofs).getOrThrow()
            }
        }
    }

    @Test
    fun `when token endpoint returns authorization_details they are parsed properly`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            nonceEndpointMocker(),
            tokenPostMockerWithAuthDetails(
                listOf(CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
            ),
            singleIssuanceRequestMocker(
                credential = "credential",
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                    assertNotNull(
                        issuanceRequestTO.credentialIdentifier,
                        "Expected identifier based issuance request but credential_identifier is null",
                    )
                },
            ),
        )
        val (authorizedRequest, _) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        assertTrue("Identifiers expected to be parsed") {
            !authorizedRequest.credentialIdentifiers.isNullOrEmpty()
        }
    }

    @Test
    fun `when successful issuance response contains additional info, it is reflected in SubmissionOutcome_Success`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    respond(
                        content = """
                                {                                  
                                  "credentials": [{
                                       "credential": "credential_content",
                                       "infoObj": {
                                          "attr1": "value1",
                                          "attr2": "value2"
                                       },
                                       "infoStr": "valueStr",
                                       "infoArr": ["valueArr1", "valueArr2", "valueArr3"]                                       
                                   }],
                                  "notification_id": "valbQc6p55LS"
                                }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        with(issuer) {
            val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
            val (_, outcome) = assertDoesNotThrow {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 1)).getOrThrow()
            }
            assertIs<SubmissionOutcome.Success>(outcome)
            assertTrue { outcome.credentials.size == 1 }
            assertIs<Credential.Str>(outcome.credentials[0].credential)

            val credAdditionalInfo = outcome.credentials[0].additionalInfo
            assertNotNull(credAdditionalInfo)
            assertNull(credAdditionalInfo["credential"])
            assertIs<JsonObject>(credAdditionalInfo["infoObj"])
            assertIs<JsonPrimitive>(credAdditionalInfo["infoStr"])
            assertIs<JsonArray>(credAdditionalInfo["infoArr"])
        }
    }

    @Test
    fun `when successful issuance response does not contain 'credential' attribute fails with ResponseUnparsable exception`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    respond(
                        content = """
                                {                                  
                                  "credentials": [{
                                       "crdntial": "credential_content"                                                                          
                                   }],
                                  "notification_id": "valbQc6p55LS"
                                }
                        """.trimIndent(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
            ),
        )
        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
        )

        with(issuer) {
            val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
            val ex = assertFailsWith<JsonConvertException> {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, proofsSpecForEcKeys(Curve.P_256, 1)).getOrThrow()
            }
            assertIs<ResponseUnparsable>(ex.cause)
        }
    }
}
