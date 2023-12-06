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
import eu.europa.ec.eudi.openid4vci.internal.BatchIssuanceSuccessResponse
import eu.europa.ec.eudi.openid4vci.internal.CertificateIssuanceResponse
import eu.europa.ec.eudi.openid4vci.internal.formats.MsoMdoc
import eu.europa.ec.eudi.openid4vci.internal.formats.SdJwtVc
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceBatchRequestTest {

    val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"

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
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
    )

    @Test
    fun `successful batch issuance`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            batchIssuanceRequestMocker(
                responseBuilder = {
                    val textContent = it?.body as TextContent
                    if (textContent.text.contains("\"proof\":")) {
                        respond(
                            content = Json.encodeToString(
                                BatchIssuanceSuccessResponse(
                                    credentialResponses = listOf(
                                        CertificateIssuanceResponse(
                                            format = MsoMdoc.FORMAT,
                                            credential = "issued_credential_content_mso_mdoc",
                                        ),
                                        CertificateIssuanceResponse(
                                            format = SdJwtVc.FORMAT,
                                            credential = "issued_credential_content_sd_jwt_vc",
                                        ),
                                    ),
                                    cNonce = "wlbQc6pCJp",
                                    cNonceExpiresInSeconds = 86400,
                                ),
                            ),
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
            ) {},
        )
        val (_, authorizedRequest, issuer) =
            initIssuerWithOfferAndAuthorize(mockedKtorHttpClientFactory, CREDENTIAL_OFFER_NO_GRANTS)

        val claimSet_mso_mdoc = MsoMdoc.Model.ClaimSet(
            claims = mapOf(
                "org.iso.18013.5.1" to mapOf(
                    "given_name" to Claim(),
                    "family_name" to Claim(),
                    "birth_date" to Claim(),
                ),
            ),
        )
        val claimSet_sd_jwt_vc = SdJwtVc.Model.ClaimSet(
            claims = mapOf(
                "given_name" to Claim(),
                "family_name" to Claim(),
                "birth_date" to Claim(),
            ),
        )

        with(issuer) {
            when (authorizedRequest) {
                is AuthorizedRequest.NoProofRequired -> {
                    val credentialMetadata = listOf(
                        CredentialIdentifier(PID_MsoMdoc_SCOPE) to claimSet_mso_mdoc,
                        CredentialIdentifier(PID_SdJwtVC_SCOPE) to claimSet_sd_jwt_vc,
                    )

                    val submittedRequest =
                        authorizedRequest.requestBatch(credentialMetadata).getOrThrow()

                    when (submittedRequest) {
                        is SubmittedRequest.InvalidProof -> {
                            val proofRequired = authorizedRequest.handleInvalidProof(submittedRequest.cNonce)

                            val proofSigner = CryptoGenerator.rsaProofSigner()
                            val credentialMetadataTriples = listOf(
                                Triple(
                                    CredentialIdentifier(PID_MsoMdoc_SCOPE),
                                    claimSet_mso_mdoc,
                                    proofSigner,
                                ),
                                Triple(
                                    CredentialIdentifier(PID_SdJwtVC_SCOPE),
                                    claimSet_sd_jwt_vc,
                                    proofSigner,
                                ),
                            )

                            val response = proofRequired.requestBatch(credentialMetadataTriples).getOrThrow()

                            assertTrue("Second attempt should be successful") {
                                response is SubmittedRequest.Success
                            }

                            assertTrue("Second attempt should be successful") {
                                (response as SubmittedRequest.Success).credentials.all {
                                    it is IssuedCredential.Issued &&
                                        it.format in listOf(MsoMdoc.FORMAT, SdJwtVc.FORMAT)
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
    }

    private suspend fun initIssuerWithOfferAndAuthorize(
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
