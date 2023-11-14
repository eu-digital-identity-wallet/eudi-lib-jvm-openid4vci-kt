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
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceBatchRequestTest {

    val PID_SdJwtVC_SCOPE = "eu.europa.ec.eudiw.pid_vc_sd_jwt"
    val PID_MsoMdoc_SCOPE = "eu.europa.ec.eudiw.pid_mso_mdoc"

    private val CREDENTIAL_OFFER_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["$PID_MsoMdoc_SCOPE", "$PID_SdJwtVC_SCOPE"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `successful batch issuance`() {
        val credential_mso_mdoc = "issued_credential_content_mso_mdoc"
        val credential_sd_jwt_vc = "issued_credential_content_sd_jwt_vc"
        issuanceTestBed(
            encryptedResponses = false,
            testBlock = { client ->

                val (_, authorizedRequest, issuer) =
                    initIssuerWithOfferAndAuthorize(client, CREDENTIAL_OFFER_NO_GRANTS)

                val claimSet_mso_mdoc = MsoMdocFormat.ClaimSet(
                    claims = mapOf(
                        "org.iso.18013.5.1" to mapOf(
                            "given_name" to Claim(),
                            "family_name" to Claim(),
                            "birth_date" to Claim(),
                        ),
                    ),
                )
                val claimSet_sd_jwt_vc = SdJwtVcFormat.ClaimSet(
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
                            val credentialMetadata = listOf(
                                CredentialMetadata.ByScope(Scope.of(PID_MsoMdoc_SCOPE)) to claimSet_mso_mdoc,
                                CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE)) to claimSet_sd_jwt_vc,
                            )

                            val submittedRequest =
                                authorizedRequest.requestBatch(credentialMetadata).getOrThrow()

                            when (submittedRequest) {
                                is SubmittedRequest.InvalidProof -> {
                                    val proofRequired = authorizedRequest.handleInvalidProof(submittedRequest.cNonce)

                                    val credentialMetadataTriples = listOf(
                                        Triple(CredentialMetadata.ByScope(Scope.of(PID_MsoMdoc_SCOPE)), claimSet_mso_mdoc, bindingKey),
                                        Triple(CredentialMetadata.ByScope(Scope.of(PID_SdJwtVC_SCOPE)), claimSet_sd_jwt_vc, bindingKey),
                                    )

                                    val response = proofRequired.requestBatch(credentialMetadataTriples).getOrThrow()

                                    assertTrue("Second attempt should be successful") {
                                        response is SubmittedRequest.Success
                                    }

                                    assertTrue("Second attempt should be successful") {
                                        (response as SubmittedRequest.Success).response.credentialResponses.all {
                                            it is CredentialIssuanceResponse.Result.Issued &&
                                                it.format in listOf(MsoMdocFormat.FORMAT, SdJwtVcFormat.FORMAT)
                                        }
                                    }
                                }

                                is SubmittedRequest.Failed -> fail(
                                    "Failed with error ${submittedRequest.error}",
                                )

                                is SubmittedRequest.Success -> fail(
                                    "first attempt should be unsuccessful",
                                )
                            }
                        }

                        is AuthorizedRequest.ProofRequired ->
                            fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                    }
                }
            },
            issuanceRequestAssertions = { call ->
                val request =
                    call.receive<CredentialIssuanceRequestTO>() as CredentialIssuanceRequestTO.BatchCredentialsTO

                println(request)

                val proofsProvided = request.credentialRequests.any {
                    it.proof != null
                }

                if (proofsProvided) {
                    call.respond(
                        HttpStatusCode.OK,
                        BatchIssuanceSuccessResponse(
                            credentialResponses = listOf(
                                BatchIssuanceSuccessResponse.CertificateIssuanceResponse(
                                    format = MsoMdocFormat.FORMAT,
                                    credential = credential_mso_mdoc,
                                ),
                                BatchIssuanceSuccessResponse.CertificateIssuanceResponse(
                                    format = SdJwtVcFormat.FORMAT,
                                    credential = credential_sd_jwt_vc,
                                ),
                            ),
                            cNonce = "wlbQc6pCJp",
                            cNonceExpiresInSeconds = 86400,
                        ),
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

    private suspend fun initIssuerWithOfferAndAuthorize(
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
