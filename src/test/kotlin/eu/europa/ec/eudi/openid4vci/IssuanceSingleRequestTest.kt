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
import eu.europa.ec.eudi.openid4vci.internal.Proof
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.formats.IdentifierBasedIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.formats.MsoMdocIssuanceRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.assertDoesNotThrow
import java.net.URI
import java.util.*
import kotlin.test.*

private const val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
private const val PID_SdJwtVC_ID = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
private const val PID_MsoMdoc_ID = "eu.europa.ec.eudiw.pid_mso_mdoc"
private val CredentialOffer = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC_ID", "$PID_MsoMdoc_ID"]          
        }
""".trimIndent()
private val CredentialOfferMsoMdoc = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_MsoMdoc_ID"]          
        }
""".trimIndent()
private val CredentialOfferWithSdJwtVc = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credential_configuration_ids": ["$PID_SdJwtVC_ID"]          
        }
""".trimIndent()

class IssuanceSingleRequestTest {

    private val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    )

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
                    val issuanceRequestTO = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text)
                    assertThat(
                        "Wrong credential request type",
                        issuanceRequestTO is CredentialIssuanceRequestTO.SingleCredentialTO,
                    )
                },
            ),
        )
        val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferMsoMdoc,
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
                    val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                    val submittedRequest = assertDoesNotThrow {
                        authorizedRequest.requestSingle(credentialConfigurationId to null, claimSet).getOrThrow()
                    }
                    assertIs<SubmittedRequest.InvalidProof>(submittedRequest)
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
        val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferMsoMdoc,
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
                    val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                    val request = assertDoesNotThrow {
                        authorizedRequest.requestSingle(credentialConfigurationId to null, claimSet).getOrThrow()
                    }
                    assertIs<SubmittedRequest.Failed>(request)
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
        val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOffer,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val claimSetMsoMdoc = MsoMdocClaimSet(listOf("org.iso.18013.5.1" to "degree"))
                    var credentialConfigurationId = CredentialConfigurationIdentifier(PID_MsoMdoc_ID)
                    assertFailsWith<CredentialIssuanceError.InvalidIssuanceRequest> {
                        authorizedRequest.requestSingle(credentialConfigurationId to null, claimSetMsoMdoc).getOrThrow()
                    }

                    val claimSetSdJwtVc = GenericClaimSet(listOf("degree"))
                    credentialConfigurationId = CredentialConfigurationIdentifier(PID_SdJwtVC_ID)
                    assertFailsWith<CredentialIssuanceError.InvalidIssuanceRequest> {
                        authorizedRequest.requestSingle(credentialConfigurationId to null, claimSetSdJwtVc).getOrThrow()
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
        val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOffer,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialConfigurationId = CredentialConfigurationIdentifier("UniversityDegree")
                    assertFailsWith<IllegalArgumentException> {
                        authorizedRequest.requestSingle(credentialConfigurationId to null, null).getOrThrow()
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
                    val issuanceRequest = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text) as MsoMdocIssuanceRequestTO
                    issuanceRequest.proof?.let {
                        assertIs<Proof.Jwt>(issuanceRequest.proof)
                    }
                },
            ),
        )

        val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferMsoMdoc,
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
                    val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                    val requestCredentialIdentifier = credentialConfigurationId to null
                    val submittedRequest = authorizedRequest.requestSingle(requestCredentialIdentifier, claimSet).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired = authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val response = assertDoesNotThrow {
                                proofRequired.requestSingle(
                                    requestCredentialIdentifier,
                                    claimSet,
                                    CryptoGenerator.rsaProofSigner(),
                                ).getOrThrow()
                            }
                            assertIs<SubmittedRequest.Success>(response)
                        }

                        is SubmittedRequest.Failed -> fail(
                            "Failed with error ${submittedRequest.error}",
                        )

                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired -> fail(
                    "State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint",
                )
            }
        }
    }

    @Test
    fun `successful issuance of credential in vc+sd-jwt format`() = runTest {
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

        val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOfferWithSdJwtVc,
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
                    val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                    val configurationBasedIdentifier = credentialConfigurationId to null
                    val submittedRequest = authorizedRequest.requestSingle(configurationBasedIdentifier, claimSet).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired = authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val response = assertDoesNotThrow {
                                proofRequired.requestSingle(
                                    configurationBasedIdentifier,
                                    claimSet,
                                    CryptoGenerator.rsaProofSigner(),
                                ).getOrThrow()
                            }
                            assertIs<SubmittedRequest.Success>(response)
                        }

                        is SubmittedRequest.Failed -> fail("Failed with error ${submittedRequest.error}")
                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
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
                    val issuanceRequestTO = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text)
                    assertThat(
                        "Wrong credential request type",
                        issuanceRequestTO is IdentifierBasedIssuanceRequestTO,
                    )
                },
            ),
        )
        val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOffer,
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialIdentifier = authorizedRequest.credentialIdentifiers?.let {
                        it.entries.first().key to it.entries.first().value[0]
                    } ?: error("No credential identifier")
                    authorizedRequest.requestSingle(credentialIdentifier, null).getOrThrow()
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
                    val issuanceRequestTO = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text)
                    assertThat(
                        "Wrong credential request type",
                        issuanceRequestTO is IdentifierBasedIssuanceRequestTO,
                    )
                },
            ),
        )
        val (_, authorizedRequest, _) = authorizeRequestForCredentialOffer(
            mockedKtorHttpClientFactory,
            CredentialOffer,
        )

        assertTrue("Identifiers expected to be parsed") {
            !authorizedRequest.credentialIdentifiers.isNullOrEmpty()
        }
    }

    private suspend fun authorizeRequestForCredentialOffer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialOfferStr: String,
    ): Triple<CredentialOffer, AuthorizedRequest, Issuer> {
        val offer = CredentialOfferRequestResolver(ktorHttpClientFactory = ktorHttpClientFactory)
            .resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()

        val issuer = Issuer.make(
            config = vciWalletConfiguration,
            credentialOffer = offer,
            ktorHttpClientFactory = ktorHttpClientFactory,
        )

        val authorizedRequest = with(issuer) {
            val parRequested = prepareAuthorizationRequest().getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested.authorizeWithAuthorizationCode(AuthorizationCode(authorizationCode)).getOrThrow()
        }
        return Triple(offer, authorizedRequest, issuer)
    }
}
