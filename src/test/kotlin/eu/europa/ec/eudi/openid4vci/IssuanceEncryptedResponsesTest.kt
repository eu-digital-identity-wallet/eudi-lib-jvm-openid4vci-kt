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
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.*
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialIssuanceRequestTO
import eu.europa.ec.eudi.openid4vci.internal.formats.MsoMdoc
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
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

    val CREDENTIAL_ISSUER_PUBLIC_URL = "https://credential-issuer.example.com"

    private val AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS = """
        {
          "credential_issuer": "$CREDENTIAL_ISSUER_PUBLIC_URL",
          "credentials": ["eu.europa.ec.eudiw.pid_mso_mdoc"]          
        }
    """.trimIndent()

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `when encryption algorithm is not supported by issuer then throw ResponseEncryptionAlgorithmNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                        )
                    },
                ),
            )
            val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
            )

            val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_384,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            assertFailsWith<ResponseEncryptionAlgorithmNotSupportedByIssuer>(
                block = {
                    with(issuer) {
                        noProofRequired.requestSingle(offer.credentials[0], null).getOrThrow()
                    }
                },
            )
        }

    @Test
    fun `when issuance request encryption method is not supported by issuer then throw ResponseEncryptionMethodNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                        )
                    },
                ),
            )
            val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
            )
            val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A256GCM,
            )

            assertFailsWith<ResponseEncryptionMethodNotSupportedByIssuer>(
                block = {
                    with(issuer) {
                        noProofRequired.requestSingle(offer.credentials[0], null).getOrThrow()
                    }
                },
            )
        }

    @Test
    fun `when issuer does not support encrypted responses but request contains encryption metadata then throw exception`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_no_encryption.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                        )
                    },
                ),
            )
            val (offer, authorizedRequest, issuer) =
                initIssuerWithOfferAndAuthorize(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS)

            val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            assertFailsWith<IssuerDoesNotSupportEncryptedResponses> {
                with(issuer) {
                    noProofRequired
                        .requestSingle(offer.credentials[0], null).getOrThrow()
                }
            }
        }

    @Test
    fun `when issuer demands encrypted responses but request does not contain encryption metadata then throw exception`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                        )
                    },
                ),
            )
            val (offer, authorizedRequest, issuer) = initIssuerWithOfferAndAuthorize(
                mockedKtorHttpClientFactory,
                AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS,
            )

            val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired

            assertFailsWith<IssuerExpectsResponseEncryptionCryptoMaterialButNotProvided>(
                block = {
                    with(issuer) {
                        noProofRequired
                            .requestSingle(offer.credentials[0], null).getOrThrow()
                    }
                },
            )
        }

    @Test
    fun `when issuer forces encrypted responses, request must include response encryption material`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                RequestMocker(
                    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                    responseBuilder = {
                        respond(
                            content = getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json"),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                        )
                    },
                ),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        val textContent = it?.body as TextContent
                        if (textContent.text.contains("\"proof\":")) {
                            val issuanceRequestTO = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text)
                            issuanceRequestTO as CredentialIssuanceRequestTO.SingleCredentialTO
                            val jwk = JWK.parse(issuanceRequestTO.credentialEncryptionJwk.toString())
                            val alg = JWEAlgorithm.parse(issuanceRequestTO.credentialResponseEncryptionAlg)
                            val enc = EncryptionMethod.parse(issuanceRequestTO.credentialResponseEncryptionMethod)
                            respond(
                                content = encryptedResponse(jwk, alg, enc).getOrThrow(),
                                status = HttpStatusCode.OK,
                                headers = headersOf(
                                    HttpHeaders.ContentType to listOf("application/jwt"),
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
                        assertTrue("No Authorization header passed.") {
                            it.headers.contains("Authorization")
                        }
                        assertTrue("Authorization header malformed.") {
                            it.headers.get("Authorization")?.contains("BEARER") ?: false
                        }
                        assertTrue("Content Type must be application/json") {
                            it.body.contentType == ContentType.parse("application/json")
                        }

                        val textContent = it.body as TextContent
                        val issuanceRequestTO = Json.decodeFromString<CredentialIssuanceRequestTO>(textContent.text)
                        assertTrue("Wrong credential request type") {
                            issuanceRequestTO is CredentialIssuanceRequestTO.SingleCredentialTO
                        }
                        assertTrue("Missing response encryption JWK") {
                            issuanceRequestTO is CredentialIssuanceRequestTO.SingleCredentialTO &&
                                    issuanceRequestTO.credentialEncryptionJwk != null
                        }
                        assertTrue("Missing response encryption algorithm") {
                            issuanceRequestTO is CredentialIssuanceRequestTO.SingleCredentialTO &&
                                    issuanceRequestTO.credentialResponseEncryptionAlg != null
                        }
                        assertTrue("Missing response encryption method") {
                            issuanceRequestTO is CredentialIssuanceRequestTO.SingleCredentialTO &&
                                    issuanceRequestTO.credentialResponseEncryptionMethod != null
                        }
                    },
                ),
            )
            val claimSet = MsoMdoc.Model.ClaimSet(
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
                initIssuerWithOfferAndAuthorize(mockedKtorHttpClientFactory, AUTH_CODE_GRANT_CREDENTIAL_OFFER_NO_GRANTS)

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
                                val response =
                                    proofRequired.requestSingle(credentialMetadata, claimSet, bindingKey)
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

        val flowState = with(issuer) {
            val parRequested = issuer.pushAuthorizationCodeRequest(offer.credentials, null).getOrThrow()
            val authorizationCode = UUID.randomUUID().toString()
            parRequested
                .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                .requestAccessToken().getOrThrow()
        }
        return Triple(offer, flowState, issuer)
    }

    private fun encryptedResponse(jwk: JWK, alg: JWEAlgorithm, enc: EncryptionMethod): Result<String> {
        val jsonObject =
            buildJsonObject {
                put("format", "mso_mdoc")
                put("credential", "issued_credential")
                put("c_nonce", "wlbQc6pCJp")
                put("c_nonce_expires_in", 86400)
            }
        val jsonStr = Json.encodeToString(jsonObject)
        return encypt(JWTClaimsSet.parse(jsonStr), jwk, alg, enc)
    }

    fun encypt(claimSet: JWTClaimsSet, jwk: JWK, alg: JWEAlgorithm, enc: EncryptionMethod): Result<String> =
        runCatching {
            randomRSAEncryptionKey(2048)
            val header =
                JWEHeader.Builder(alg, enc)
                    .jwk(jwk.toPublicJWK())
                    .keyID(jwk.keyID)
                    .type(JOSEObjectType.JWT)
                    .build()

            val jwt = EncryptedJWT(header, claimSet)
            val encrypter =
                when (jwk) {
                    is RSAKey -> RSAEncrypter(jwk)
                    is ECKey -> ECDHEncrypter(jwk)
                    else -> throw IllegalArgumentException("unsupported 'kty': '${jwk.keyType.value}'")
                }

            jwt.encrypt(encrypter)
            jwt.serialize()
        }
}
