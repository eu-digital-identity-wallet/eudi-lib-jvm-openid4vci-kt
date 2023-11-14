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

import com.nimbusds.jose.JWSAlgorithm
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import org.hamcrest.MatcherAssert.assertThat
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.fail

class IssuanceSingleRequestTest {

    val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
    val PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"

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
    )

    @Test
    fun `when issuance requested with no proof then InvalidProof error is raised with c_nonce passed`() {
        issuanceTestBed(
            { client ->

                val (offer, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc)

                val claimSet = MsoMdocFormat.ClaimSet(
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
            },
            { call ->

                assertThat(
                    "No Authorization header passed .",
                    call.request.headers["Authorization"] != null,
                )
                call.request.headers["Authorization"]?.let {
                    assertThat(
                        "No Authorization header passed .",
                        it.contains("BEARER"),
                    )
                }
                assertThat(
                    "Content Type must be application/json",
                    call.request.headers["Content-Type"] == "application/json",
                )

                val request = call.receive<CredentialIssuanceRequestTO>()
                assertThat(
                    "Wrong credential request type",
                    request is CredentialIssuanceRequestTO.SingleCredentialTO,
                )

                call.respondText(
                    """
                            {
                                "error": "invalid_proof",
                                "c_nonce": "ERE%@^TGWYEYWEY",
                                "c_nonce_expires_in": 34
                            } 
                    """.trimIndent(),
                    ContentType.parse("application/json"),
                    HttpStatusCode.BadRequest,
                )
            },
        )
    }

    @Test
    fun `when issuer responds with 'invalid_proof' and no c_nonce then ResponseUnparsable error is returned `() {
        issuanceTestBed(
            { client ->

                val (offer, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc)

                val claimSet = MsoMdocFormat.ClaimSet(
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
            },
            { call ->
                call.respondText(
                    """
                            {
                                "error": "invalid_proof"                                
                            } 
                    """.trimIndent(),
                    ContentType.parse("application/json"),
                    HttpStatusCode.BadRequest,
                )
            },
        )
    }

    @Test
    fun `when issuer request contains unsupported claims exception CredentialIssuanceException is thrown`() {
        issuanceTestBed(
            { client ->
                val (_, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc)

                with(issuer) {
                    when (authorizedRequest) {
                        is AuthorizedRequest.NoProofRequired -> {
                            val claimSet_mso_mdoc =
                                MsoMdocFormat.ClaimSet(mapOf("org.iso.18013.5.1" to mapOf("degree" to Claim())))
                            var credentialMetadata = CredentialMetadata.ByScope(Scope.of(PID_MsoMdoc_SCOPE))
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

                            val claimSet_sd_jwt_vc = SdJwtVcFormat.ClaimSet(mapOf("degree" to Claim()))
                            credentialMetadata = CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE))
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
            },
            {},
        )
    }

    @Test
    fun `successful issuance of credential in mso_mdoc format`() {
        val credential = "issued_credential_content_mso_mdoc"
        issuanceTestBed(
            { client ->

                val (offer, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_mso_mdoc)

                val claimSet = MsoMdocFormat.ClaimSet(
                    claims = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "given_name" to Claim(),
                            "family_name" to Claim(),
                            "birth_date" to Claim(),
                        ),
                    ),
                )
                val bindingKey = BindingKey.Jwk(
                    algorithm = JWSAlgorithm.RS256,
                    jwk = KeyGenerator.randomRSASigningKey(2048),
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
                                        bindingKey,
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
            },
            { call ->

                val request =
                    call.receive<CredentialIssuanceRequestTO>() as MsoMdocFormat.CredentialIssuanceRequestTO
                println(request)
                if (request.proof != null) {
                    call.respondText(
                        """
                                {
                                  "format": "mso_mdoc",
                                  "credential": "$credential",
                                  "c_nonce": "wlbQc6pCJp",
                                  "c_nonce_expires_in": 86400
                                }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.OK,
                    )
                } else {
                    call.respondText(
                        """
                            {
                                "error": "invalid_proof",
                                "c_nonce": "ERE%@^TGWYEYWEY",
                                "c_nonce_expires_in": 34
                            } 
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    @Test
    fun `successful issuance of credential in vc+sd-jwt format`() {
        val credential = "issued_credential_content_vc+sd-jwt"
        issuanceTestBed(
            { client ->

                val (offer, authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS_vc_sd_jwt)

                val claimSet = SdJwtVcFormat.ClaimSet(
                    claims = mapOf(
                        "given_name" to Claim(),
                        "family_name" to Claim(),
                        "birth_date" to Claim(),
                    ),
                )
                val bindingKey = BindingKey.Jwk(
                    algorithm = JWSAlgorithm.RS256,
                    jwk = KeyGenerator.randomRSASigningKey(2048),
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
                                    val response = proofRequired.requestSingle(credentialMetadata, claimSet, bindingKey)
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
            },
            { call ->

                val request =
                    call.receive<CredentialIssuanceRequestTO>() as SdJwtVcFormat.CredentialIssuanceRequestTO
                println(request)
                if (request.proof != null) {
                    call.respondText(
                        """
                                {
                                  "format": "vc+sd-jwt",
                                  "credential": "$credential",
                                  "c_nonce": "wlbQc6pCJp",
                                  "c_nonce_expires_in": 86400
                                }
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.OK,
                    )
                } else {
                    call.respondText(
                        """
                            {
                                "error": "invalid_proof",
                                "c_nonce": "ERE%@^TGWYEYWEY",
                                "c_nonce_expires_in": 34
                            } 
                        """.trimIndent(),
                        ContentType.parse("application/json"),
                        HttpStatusCode.BadRequest,
                    )
                }
            },
        )
    }

    private suspend fun authorizeRequestForCredentialOffer(
        client: HttpClient,
        credentialOfferStr: String,
    ): Triple<CredentialOffer, AuthorizedRequest, Issuer> {
        val offer = CredentialOfferRequestResolver(
            httpGet = createGetASMetadata(client),
        ).resolve("https://$CREDENTIAL_ISSUER_PUBLIC_URL/credentialoffer?credential_offer=$credentialOfferStr")
            .getOrThrow()

        val issuer = Issuer.make(
            IssuanceAuthorizer.make(
                offer.authorizationServerMetadata,
                vciWalletConfiguration,
                createPostPar(client),
                createGetAccessToken(client),
            ),
            IssuanceRequester.make(
                issuerMetadata = offer.credentialIssuerMetadata,
                postIssueRequest = createPostIssuance(client),
            ),
        )

        val authorizedRequest = with(issuer) {
            val parRequested = issuer.pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
        return Triple(offer, authorizedRequest, issuer)
    }
}
