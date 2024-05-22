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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.*
import eu.europa.ec.eudi.openid4vci.internal.http.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.assertDoesNotThrow
import java.util.*
import kotlin.test.*

class IssuanceEncryptedResponsesTest {

    @Test
    fun `when encryption algorithm is not supported by issuer then throw ResponseEncryptionAlgorithmNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
            )
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_384,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            assertFailsWith<ResponseEncryptionAlgorithmNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        ktorHttpClientFactory = mockedKtorHttpClientFactory,
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                    )
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
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
            )
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A256GCM,
            )

            assertFailsWith<ResponseEncryptionMethodNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        ktorHttpClientFactory = mockedKtorHttpClientFactory,
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                    )
                },
            )
        }

    @Test
    fun `response encryption unsupported by issuer, required by wallet, then ResponseEncryptionRequiredByWalletButNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.NOT_SUPPORTED),
            )
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A256GCM,
            )

            assertFailsWith<ResponseEncryptionRequiredByWalletButNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        ktorHttpClientFactory = mockedKtorHttpClientFactory,
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                        config = OpenId4VCIConfiguration.copy(
                            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.REQUIRED,
                        ),
                    )
                },
            )
        }

    @Test
    fun `no crypto material generated when required, then WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.SUPPORTED_NOT_REQUIRED),
            )

            assertFailsWith<WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated>(
                block = {
                    authorizeRequestForCredentialOffer(
                        ktorHttpClientFactory = mockedKtorHttpClientFactory,
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> null },
                        config = OpenId4VCIConfiguration.copy(
                            credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.REQUIRED,
                        ),
                    )
                },
            )
        }

    @Test
    fun `when issuer does not support encrypted responses encryption spec is ignored in submitted request`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.NOT_SUPPORTED),
                singleIssuanceRequestMocker(
                    requestValidator = {
                        val textContent = it.body as TextContent
                        val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                        assertTrue("No encryption parameters expected to be sent") {
                            issuanceRequestTO.credentialResponseEncryption == null
                        }
                    },
                ),
            )
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
                val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
                noProofRequired.requestSingle(requestPayload).getOrThrow()
            }
        }

    @Test
    fun `when issuer supports but not mandates encrypted responses, client can request encrypted responses`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.SUPPORTED_NOT_REQUIRED),
                singleIssuanceRequestMocker(
                    requestValidator = {
                        val textContent = it.body as TextContent
                        val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                        assertTrue("Encryption parameters were expected to be sent but was not.") {
                            issuanceRequestTO.credentialResponseEncryption != null
                        }
                    },
                ),
            )
            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
                val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
                noProofRequired.requestSingle(requestPayload).getOrThrow()
            }
        }

    @Test
    fun `when issuer supports but not mandates encrypted responses, client can request NON encrypted responses`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.SUPPORTED_NOT_REQUIRED),
                singleIssuanceRequestMocker(
                    requestValidator = {
                        val textContent = it.body as TextContent
                        val issuanceRequestTO = Json.decodeFromString<CredentialRequestTO>(textContent.text)
                        assertTrue("Encryption parameters were expected to be sent but was not.") {
                            issuanceRequestTO.credentialResponseEncryption == null
                        }
                    },
                ),
            )
            val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> null },
            )

            with(issuer) {
                val noProofRequired = authorizedRequest as AuthorizedRequest.NoProofRequired
                val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, null)
                noProofRequired.requestSingle(requestPayload).getOrThrow()
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, request must include response encryption material`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptedResponseDataBuilder(it) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credential = "issued_credential",
                                    notificationId = "fgh126lbHjtspVbn",
                                    cNonce = "wlbQc6pCJp",
                                    cNonceExpiresInSeconds = 86400,
                                ),
                            )
                        }
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
                        val issuanceRequestTO = assertDoesNotThrow("Wrong credential request type") {
                            Json.decodeFromString<CredentialRequestTO>(textContent.text)
                        }
                        assertTrue("Missing response encryption JWK") {
                            issuanceRequestTO.credentialResponseEncryption?.jwk != null
                        }
                        assertTrue("Missing response encryption algorithm") {
                            issuanceRequestTO.credentialResponseEncryption?.encryptionAlgorithm != null
                        }
                        assertTrue("Missing response encryption method") {
                            issuanceRequestTO.credentialResponseEncryption?.encryptionMethod != null
                        }
                    },
                ),
            )
            val claimSet = MsoMdocClaimSet(
                claims = listOf(
                    "org.iso.18013.5.1" to "given_name",
                    "org.iso.18013.5.1" to "family_name",
                    "org.iso.18013.5.1" to "birth_date",
                ),
            )

            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (offer, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)
                val credentialConfigurationId = offer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId, claimSet)
                val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()
                assertIs<SubmittedRequest.Success>(submittedRequest)
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, batch request must not include encryption spec in its individual single requests`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
                batchIssuanceRequestMocker(
                    responseBuilder = { TODO("Not needed") },
                    requestValidator = {
                        val textContent = it.body as TextContent
                        val batchRequestTO = assertDoesNotThrow("Wrong credential request type") {
                            Json.decodeFromString<BatchCredentialRequestTO>(textContent.text)
                        }
                        assertTrue("Missing response encryption JWK") {
                            batchRequestTO.credentialResponseEncryption?.jwk != null
                        }
                        assertTrue("Missing response encryption algorithm") {
                            batchRequestTO.credentialResponseEncryption?.encryptionAlgorithm != null
                        }
                        assertTrue("Missing response encryption method") {
                            batchRequestTO.credentialResponseEncryption?.encryptionMethod != null
                        }
                        assertTrue("Individual single requests must not include encryption specification") {
                            batchRequestTO.credentialRequests.all { it.credentialResponseEncryption == null }
                        }
                    },
                ),
            )

            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CREDENTIAL_OFFER_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)

                val batchRequestPayload = listOf(
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_MsoMdoc),
                        null,
                    ),
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SdJwtVC),
                        null,
                    ),
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(DEGREE_JwtVcJson),
                        null,
                    ),
                )
                authorizedRequest.requestBatch(batchRequestPayload)
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, batch response is encrypted and parsable`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
                batchIssuanceRequestMocker(
                    responseBuilder = {
                        encryptedResponseDataBuilder(it) {
                            Json.encodeToString(
                                BatchCredentialResponseSuccessTO(
                                    credentialResponses = listOf(
                                        IssuanceResponseTO(
                                            transactionId = "jjj136kojtspbnq",
                                        ),
                                        IssuanceResponseTO(
                                            credential = "${PID_MsoMdoc}_issued_credential",
                                            notificationId = "fgh126lbHjtspVbn",
                                        ),
                                        IssuanceResponseTO(
                                            credential = "${DEGREE_JwtVcJson}_issued_credential",
                                            notificationId = "aaffbnmyw23lbHjtspVbn",
                                        ),
                                    ),
                                    cNonce = "wlbQc6pCJp",
                                    cNonceExpiresInSeconds = 86400,
                                ),
                            )
                        }
                    },
                    requestValidator = {},
                ),
            )

            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CREDENTIAL_OFFER_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)

                val batchRequestPayload = listOf(
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_MsoMdoc),
                        null,
                    ),
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SdJwtVC),
                        null,
                    ),
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(DEGREE_JwtVcJson),
                        null,
                    ),
                )
                authorizedRequest.requestBatch(batchRequestPayload).fold(
                    onSuccess = {
                        assertIs<SubmittedRequest.Success>(it)
                        assertTrue("One deferred credential response expected") {
                            it.credentials.any { credential -> credential is IssuedCredential.Deferred }
                        }
                    },
                    onFailure = { fail("Failed with error ${it.message}") },
                )
            }
        }

    @Test
    fun `when issuance request mandates encrypted responses and deferred response is not encrypted, throw InvalidResponseContentType`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                oidcWellKnownMocker(EncryptedResponses.REQUIRED),
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptedResponseDataBuilder(it) {
                            """ { "transaction_id": "1234565768122" } """.trimIndent()
                        }
                    },
                ),
                deferredIssuanceRequestMocker(
                    responseBuilder = { defaultIssuanceResponseDataBuilder(true) },
                ),
            )

            val issuanceResponseEncryptionSpec = IssuanceResponseEncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                algorithm = JWEAlgorithm.RSA_OAEP_256,
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                ktorHttpClientFactory = mockedKtorHttpClientFactory,
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
            )

            with(issuer) {
                assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                    CredentialConfigurationIdentifier(PID_SdJwtVC),
                    null,
                )
                val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()
                assertIs<SubmittedRequest.Success>(submittedRequest)
                val deferredCredential = submittedRequest.credentials[0]
                assertIs<IssuedCredential.Deferred>(deferredCredential)

                assertFailsWith<CredentialIssuanceError.InvalidResponseContentType>(
                    block = {
                        authorizedRequest.queryForDeferredCredential(
                            deferredCredential,
                            submittedRequest.responseEncryptionSpec,
                        ).getOrThrow()
                    },
                )
            }
        }

    @Test
    fun `when initial issuance request mandates encrypted responses, deferred responses must be encrypted`() = runTest {
        val responseEncryption = IssuanceResponseEncryptionSpec(
            jwk = randomRSAEncryptionKey(2048),
            algorithm = JWEAlgorithm.RSA_OAEP_256,
            encryptionMethod = EncryptionMethod.A128CBC_HS256,
        )
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            oidcWellKnownMocker(EncryptedResponses.REQUIRED),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    encryptedResponseDataBuilder(it) {
                        """ { "transaction_id": "1234565768122" } """.trimIndent()
                    }
                },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = {
                    val responseJson = """
                            {                     
                              "credential": "credential_content",
                              "c_nonce": "ERE%@^TGWYEYWEY",
                              "c_nonce_expires_in": 34
                            }
                    """.trimIndent()
                    respond(
                        content = encypt(
                            JWTClaimsSet.parse(responseJson),
                            responseEncryption.jwk,
                            responseEncryption.algorithm,
                            responseEncryption.encryptionMethod,
                        ).getOrThrow(),
                        status = HttpStatusCode.OK,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/jwt"),
                        ),
                    )
                },
            ),
        )

        val (_, authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            ktorHttpClientFactory = mockedKtorHttpClientFactory,
            credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
            responseEncryptionSpecFactory = { _, _ -> responseEncryption },
        )

        with(issuer) {
            assertIs<AuthorizedRequest.NoProofRequired>(authorizedRequest)
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
                null,
            )
            val submittedRequest = authorizedRequest.requestSingle(requestPayload).getOrThrow()
            assertIs<SubmittedRequest.Success>(submittedRequest)

            val deferredCredential = submittedRequest.credentials[0]
            assertIs<IssuedCredential.Deferred>(deferredCredential)

            val response = authorizedRequest.queryForDeferredCredential(
                deferredCredential,
                submittedRequest.responseEncryptionSpec,
            ).getOrThrow()

            assertIs<DeferredCredentialQueryOutcome.Issued>(response)
        }
    }
}

fun randomRSAEncryptionKey(size: Int): RSAKey = RSAKeyGenerator(size)
    .keyUse(KeyUse.ENCRYPTION)
    .keyID(UUID.randomUUID().toString())
    .issueTime(Date(System.currentTimeMillis()))
    .generate()
