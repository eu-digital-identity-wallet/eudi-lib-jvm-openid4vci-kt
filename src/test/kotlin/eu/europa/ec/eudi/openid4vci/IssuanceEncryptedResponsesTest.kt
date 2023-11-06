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

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.client.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.hamcrest.MatcherAssert.assertThat
import java.net.URI
import java.util.*
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

class IssuanceEncryptedResponsesTest {

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["PID_mso_mdoc"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    val issuanceResponseEncryption = IssuanceResponseEncryption(
        jwk = randomRSAEncryptionKey(2048),
        algorithm = JWEAlgorithm.RSA_OAEP_256,
        encryptionMethod = EncryptionMethod.A128CBC_HS256,
    )

    @Test
    fun `when issuance request encryption is not supported by issuer then throw ResponseEncryptionAlgorithmNotSupportedByIssuer`() {
        issuanceTestBed(
            encryptedResponses = true,
            testBlock = { client ->
                runBlocking {
                    val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                        client,
                        AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
                    )

                    val issuanceResponseEncryption = IssuanceResponseEncryption(
                        jwk = randomRSAEncryptionKey(2048),
                        algorithm = JWEAlgorithm.A128GCMKW,
                        encryptionMethod = EncryptionMethod.A128CBC_HS256,
                    )

                    val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired

                    var exception = assertFailsWith<CredentialIssuanceException>(
                        block = {
                            with(issuer) {
                                noProofRequired.requestSingle(offer.credentials[0], null, issuanceResponseEncryption).getOrThrow()
                            }
                        },
                    )
                    assertTrue(
                        exception.error is CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionAlgorithmNotSupportedByIssuer,
                    )
                }
            },
            issuanceRequestPostAssertions = { },
        )
    }

    @Test
    fun `when issuance request encryption method is not supported by issuer then throw ResponseEncryptionMethodNotSupportedByIssuer`() {
        issuanceTestBed(
            encryptedResponses = true,
            testBlock = { client ->
                runBlocking {
                    val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                        client,
                        AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
                    )

                    val issuanceResponseEncryption = IssuanceResponseEncryption(
                        jwk = randomRSAEncryptionKey(2048),
                        algorithm = JWEAlgorithm.RSA_OAEP_256,
                        encryptionMethod = EncryptionMethod.A128GCM,
                    )

                    val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired

                    var exception = assertFailsWith<CredentialIssuanceException>(
                        block = {
                            with(issuer) {
                                noProofRequired.requestSingle(offer.credentials[0], null, issuanceResponseEncryption).getOrThrow()
                            }
                        },
                    )
                    assertTrue(
                        exception.error is CredentialIssuanceError.ResponseEncryptionError.ResponseEncryptionMethodNotSupportedByIssuer,
                    )
                }
            },
            issuanceRequestPostAssertions = { },
        )
    }

    @Test
    fun `when issuer does not support encrypted responses but request contains encryption metadata then throw exception`() {
        issuanceTestBed(
            encryptedResponses = false,
            testBlock = { client ->
                runBlocking {
                    val (offer, authorizedRequest, issuer) =
                        initIssuerWithOfferAndAuthorize(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS)

                    val issuanceResponseEncryption = IssuanceResponseEncryption(
                        jwk = randomRSAEncryptionKey(2048),
                        algorithm = JWEAlgorithm.RSA_OAEP_256,
                        encryptionMethod = EncryptionMethod.A128GCM,
                    )

                    val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired

                    var exception = assertFailsWith<CredentialIssuanceException>(
                        block = {
                            with(issuer) {
                                noProofRequired.requestSingle(offer.credentials[0], null, issuanceResponseEncryption).getOrThrow()
                            }
                        },
                    )
                    assertTrue(exception.error is CredentialIssuanceError.ResponseEncryptionError.IssuerDoesNotSupportEncryptedResponses)
                }
            },
            issuanceRequestPostAssertions = { },
        )
    }

    @Test
    fun `when issuer demands encrypted responses but request does not contain encryption metadata then throw exception`() {
        issuanceTestBed(
            encryptedResponses = true,
            testBlock = { client ->
                runBlocking {
                    val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                        client,
                        AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
                    )

                    val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired

                    var exception = assertFailsWith<CredentialIssuanceException>(
                        block = {
                            with(issuer) {
                                noProofRequired.requestSingle(offer.credentials[0], null, null).getOrThrow()
                            }
                        },
                    )
                    assertTrue(
                        exception.error is
                            CredentialIssuanceError.ResponseEncryptionError.IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided,
                    )
                }
            },
            issuanceRequestPostAssertions = { },
        )
    }

    @Test
    fun `when issuer forces encrypted responses request must include response encryption material`() {
        issuanceTestBed(
            encryptedResponses = true,
            testBlock = { client ->
                runBlocking {
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
                        jwk = randomRSASigningKey(2048),
                    )

                    val (offer, authorizedRequest, issuer) =
                        initIssuerWithOfferAndAuthorize(client, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS)

                    with(issuer) {
                        when (authorizedRequest) {
                            is AuthorizedRequest.NoProofRequired -> {
                                val credentialMetadata = offer.credentials[0]
                                val submittedRequest =
                                    authorizedRequest.requestSingle(credentialMetadata, claimSet, issuanceResponseEncryption).getOrThrow()
                                when (submittedRequest) {
                                    is SubmittedRequest.InvalidProof -> {
                                        val proofRequired =
                                            authorizedRequest.handleInvalidProof(submittedRequest.cNonce)
                                        val response = proofRequired.requestSingle(
                                            credentialMetadata,
                                            claimSet,
                                            bindingKey,
                                            issuanceResponseEncryption,
                                        )
                                        assertThat(
                                            "Second attempt should be successful",
                                            response.getOrThrow() is SubmittedRequest.Success,
                                        )
                                    }

                                    is SubmittedRequest.Failed -> fail("Failed with error ${submittedRequest.error}")
                                    is SubmittedRequest.Success -> fail("first attempt should be un-successful")
                                }
                            }

                            is AuthorizedRequest.ProofRequired ->
                                fail("State should be Authorized.NoProofRequired when no c_nonce returned from token endpoint")
                        }
                    }
                }
            },

            issuanceRequestPostAssertions = { call ->
                runBlocking {
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

                    val requestSingle = request as CredentialIssuanceRequestTO.SingleCredentialTO
                    assertThat(
                        "Missing response encryption JWK",
                        requestSingle.credentialEncryptionJwk != null,
                    )
                    assertThat(
                        "Missing response encryption algorithm",
                        requestSingle.credentialResponseEncryptionAlg != null,
                    )
                    assertThat(
                        "Missing response encryption method",
                        requestSingle.credentialResponseEncryptionMethod != null,
                    )

                    if (request.proof != null) {
                        call.respondText(
                            encryptedResponse().getOrThrow(),
                            ContentType.parse("application/jwt"),
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
                }
            },
        )
    }

    fun randomRSAEncryptionKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.ENCRYPTION)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

    fun randomRSASigningKey(size: Int): RSAKey = RSAKeyGenerator(size)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(UUID.randomUUID().toString())
        .issueTime(Date(System.currentTimeMillis()))
        .generate()

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

        val flowState = with(issuer) {
            val parRequested = issuer.pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested
                .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
        return Triple(offer, flowState, issuer)
    }

    private fun encryptedResponse(): Result<String> {
        val jsonObject =
            buildJsonObject {
                put("format", "mso_mdoc")
                put("credential", "issued_credential")
                put("c_nonce", "wlbQc6pCJp")
                put("c_nonce_expires_in", 86400)
            }
        val jsonStr = Json.encodeToString(jsonObject)
        return encypt(JWTClaimsSet.parse(jsonStr))
    }

    fun encypt(claimSet: JWTClaimsSet): Result<String> = runCatching {
        val header = JWEHeader.Builder(issuanceResponseEncryption.algorithm, issuanceResponseEncryption.encryptionMethod)
            .jwk(issuanceResponseEncryption.jwk.toPublicJWK())
            .keyID(issuanceResponseEncryption.jwk.keyID)
            .type(JOSEObjectType.JWT)
            .build()

        val jwt = EncryptedJWT(header, claimSet)
        val encrypter =
            when (val jwk = issuanceResponseEncryption.jwk) {
                is RSAKey -> RSAEncrypter(jwk)
                is ECKey -> ECDHEncrypter(jwk)
                else -> throw IllegalArgumentException("unsupported 'kty': '${jwk.keyType.value}'")
            }

        jwt.encrypt(encrypter)
        jwt.serialize()
    }
}
