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
import eu.europa.ec.eudi.openid4vci.internal.formats.MsoMdoc
import eu.europa.ec.eudi.openid4vci.internal.formats.SdJwtVc
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.hamcrest.MatcherAssert.assertThat
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceSingleRequestTest {

    private val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"
    private val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
    private val PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["$PID_MsoMdoc_SCOPE"]          
        }
    """.trimIndent()

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["$PID_SdJwtVC_SCOPE"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
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
        val (offer, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc,
            )

        val claimSet = MsoMdocClaimSet(
            claims = mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "given_name" to Claim(),
                    "family_name" to Claim(),
                    "birth_date" to Claim(),
                ),
            ),
        )
        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialMetadata = offer.credentials[0]

                    val submittedRequest = authorizedRequest.requestSingle(credentialMetadata, claimSet)
                    assertThat(
                        "When no proof is provided while issuing result must be NonceMissing",
                        submittedRequest.getOrThrow() is SubmittedRequest.InvalidProof,
                    )
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `when issuer responds with 'invalid_proof' and no c_nonce then ResponseUnparsable error is returned `() =
        runTest {
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
            val (offer, authorizedRequest, issuer) =
                authorizeRequestForCredentialOffer(
                    mockedKtorHttpClientFactory,
                    AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc,
                )

            val claimSet = MsoMdocClaimSet(
                claims = mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "given_name" to Claim(),
                        "family_name" to Claim(),
                        "birth_date" to Claim(),
                    ),
                ),
            )
            with(issuer) {
                when (authorizedRequest) {
                    is AuthorizedRequest.NoProofRequired -> {
                        val credentialMetadata = offer.credentials[0]
                        authorizedRequest.requestSingle(credentialMetadata, claimSet)
                            .fold(
                                onSuccess = {
                                    assertThat(
                                        "Expected CredentialIssuanceException to be thrown but was not",
                                        it is SubmittedRequest.Failed &&
                                            it.error is CredentialIssuanceError.ResponseUnparsable,
                                    )
                                },
                                onFailure = {
                                    fail("No exception expected to be thrown")
                                },
                            )
                    }

                    is AuthorizedRequest.ProofRequired ->
                        fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                }
            }
        }

    @Test
    fun `when issuer request contains unsupported claims exception CredentialIssuanceException is thrown`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
        )
        val (_, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc,
            )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val claimSet_mso_mdoc =
                        MsoMdocClaimSet(mapOf("org.iso.18013.5.1" to mapOf("degree" to Claim())))
                    var credentialMetadata = CredentialIdentifier(PID_MsoMdoc_SCOPE)
                    authorizedRequest.requestSingle(credentialMetadata, claimSet_mso_mdoc)
                        .fold(
                            onSuccess = { fail("Exception expected to be thrown") },
                            onFailure = {
                                assertThat(
                                    "Expected CredentialIssuanceException to be thrown but was not",
                                    it is CredentialIssuanceError.InvalidIssuanceRequest,
                                )
                            },
                        )

                    val claimSet_sd_jwt_vc = SdJwtVcClaimSet(mapOf("degree" to Claim()))
                    credentialMetadata = CredentialIdentifier(PID_SdJwtVC_SCOPE)
                    authorizedRequest.requestSingle(credentialMetadata, claimSet_sd_jwt_vc)
                        .fold(
                            onSuccess = { fail("Exception expected to be thrown") },
                            onFailure = {
                                assertThat(
                                    "Expected CredentialIssuanceException to be thrown but was not",
                                    it is CredentialIssuanceError.InvalidIssuanceRequest,
                                )
                            },
                        )
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
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
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    val issuanceRequest =
                        Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text) as MsoMdoc.Model.CredentialIssuanceRequestTO
                    if (issuanceRequest.proof != null) {
                        respond(
                            content = """
                                {
                                  "format": "mso_mdoc",
                                  "credential": "$credential",
                                  "c_nonce": "wlbQc6pCJp",
                                  "c_nonce_expires_in": 86400
                                }
                            """.trimIndent(),
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    } else {
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
                    }
                },
                requestValidator = {
                    val textContent = it.body as TextContent
                    val issuanceRequest =
                        Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text) as MsoMdoc.Model.CredentialIssuanceRequestTO
                    issuanceRequest.proof?.let {
                        assertTrue("Not a JWT proof sent.") {
                            issuanceRequest.proof is Proof.Jwt
                        }
                    }
                },
            ),
        )

        val (offer, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc,
            )

        val claimSet = MsoMdocClaimSet(
            claims = mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "given_name" to Claim(),
                    "family_name" to Claim(),
                    "birth_date" to Claim(),
                ),
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialMetadata = offer.credentials[0]
                    val submittedRequest =
                        authorizedRequest.requestSingle(credentialMetadata, claimSet).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired =
                                authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val response = proofRequired.requestSingle(
                                credentialMetadata,
                                claimSet,
                                CryptoGenerator.rsaProofSigner(),
                            )
                            assertThat(
                                "Second attempt should be successful",
                                response.getOrThrow() is SubmittedRequest.Success,
                            )
                        }

                        is SubmittedRequest.Failed -> fail(
                            "Failed with error ${submittedRequest.error}",
                        )

                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
        }
    }

    @Test
    fun `successful issuance of credential in vc+sd-jwt format`() = runTest {
        val credential = "issued_credential_content_mso_mdoc"
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    val issuanceRequest =
                        Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text) as SdJwtVc.Model.CredentialIssuanceRequestTO
                    if (issuanceRequest.proof != null) {
                        respond(
                            content = """
                                {
                                  "format": "vc+sd-jwt",
                                  "credential": "$credential",
                                  "c_nonce": "wlbQc6pCJp",
                                  "c_nonce_expires_in": 86400
                                }
                            """.trimIndent(),
                            status = HttpStatusCode.OK,
                            headers = headersOf(
                                HttpHeaders.ContentType to listOf("application/json"),
                            ),
                        )
                    } else {
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
                    }
                },
            ),
        )

        val (offer, authorizedRequest, issuer) =
            authorizeRequestForCredentialOffer(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt,
            )

        val claimSet = SdJwtVcClaimSet(
            claims = mapOf(
                "given_name" to Claim(),
                "family_name" to Claim(),
                "birth_date" to Claim(),
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialMetadata = offer.credentials[0]
                    val submittedRequest =
                        authorizedRequest.requestSingle(credentialMetadata, claimSet).getOrThrow()
                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired =
                                authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                            val response = proofRequired.requestSingle(credentialMetadata, claimSet, CryptoGenerator.rsaProofSigner())
                            assertThat(
                                "Second attempt should be successful",
                                response.getOrThrow() is SubmittedRequest.Success,
                            )
                        }

                        is SubmittedRequest.Failed -> fail(
                            "Failed with error ${submittedRequest.error}",
                        )

                        is SubmittedRequest.Success -> fail("first attempt should be unsuccessful")
                    }
                }

                is AuthorizedRequest.ProofRequired ->
                    fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
            }
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
            authorizationServerMetadata = offer.authorizationServerMetadata,
            config = vciWalletConfiguration,
            ktorHttpClientFactory = ktorHttpClientFactory,
            issuerMetadata = offer.credentialIssuerMetadata,
        )

        val authorizedRequest = with(issuer) {
            val parRequested = issuer.pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested
                .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
        return Triple(offer, authorizedRequest, issuer)
    }
}
