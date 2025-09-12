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
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.RequestEncryptionError.IssuerRequiresEncryptedRequestButEncryptionSpecCannotBeFormulated
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError.ResponseEncryptionError.*
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.noKeyAttestationJwtProofsSpec
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialResponseSuccessTO
import eu.europa.ec.eudi.openid4vci.internal.http.DeferredRequestTO
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.*
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class IssuanceIssuerMetadataVersionTest {

    @Test
    fun `when encryption algorithm is not supported by issuer then throw ResponseEncryptionAlgorithmNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_REQUIRED),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048, JWEAlgorithm.RSA_OAEP_384),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            assertFailsWith<ResponseEncryptionAlgorithmNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                        httpClient = mockedKtorHttpClientFactory,
                    )
                },
            )
        }

    @Test
    fun `when issuance response encryption method is not supported by issuer then throw ResponseEncryptionMethodNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_REQUIRED),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A256GCM,
            )

            assertFailsWith<ResponseEncryptionMethodNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                        httpClient = mockedKtorHttpClientFactory,
                    )
                },
            )
        }

    @Test
    fun `response encryption unsupported by issuer, required by wallet, then ResponseEncryptionRequiredByWalletButNotSupportedByIssuer`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_NOT_SUPPORTED),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A256GCM,
            )

            assertFailsWith<ResponseEncryptionRequiredByWalletButNotSupportedByIssuer>(
                block = {
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfiguration.copy(
                            encryptionSupportConfig = OpenId4VCIConfiguration.encryptionSupportConfig.copy(
                                credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.REQUIRED,
                            ),
                        ),
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                        httpClient = mockedKtorHttpClientFactory,
                    )
                },
            )
        }

    @Test
    fun `no crypto material generated when required, then WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED),
            )

            assertFailsWith<WalletRequiresCredentialResponseEncryptionButNoCryptoMaterialCanBeGenerated>(
                block = {
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfiguration.copy(
                            encryptionSupportConfig = OpenId4VCIConfiguration.encryptionSupportConfig.copy(
                                credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.REQUIRED,
                            ),
                        ),
                        credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                        responseEncryptionSpecFactory = { _, _ -> null },
                        httpClient = mockedKtorHttpClientFactory,
                    )
                },
            )
        }

    @Test
    fun `when issuer does not support encrypted responses encryption spec is ignored in submitted request`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_NOT_SUPPORTED),
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
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
            }
        }

    @Test
    fun `when issuer supports but not mandates encrypted responses, client can request encrypted responses`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "issued_credential")
                                        },
                                    ),
                                    notificationId = "fgh126lbHjtspVbn",
                                ),
                            )
                        }
                    },
                    requestValidator = {
                        encryptionAwareRequestValidator<CredentialRequestTO>(it, issuerMetadataVersion) {
                            assertTrue("Encryption parameters were expected to be sent but was not.") {
                                it.credentialResponseEncryption != null
                            }
                        }
                    },
                ),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
            }
        }

    @Test
    fun `when issuer mandates encrypted requests but not supports encrypted responses, request must be encrypted and responses not`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTED_REQUEST_ONLY
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "issued_credential")
                                        },
                                    ),
                                    notificationId = "fgh126lbHjtspVbn",
                                ),
                            )
                        }
                    },
                    requestValidator = {
                        val textContent = it.body as TextContent
                        assertTrue("Request expected to be encrypted but was not") {
                            textContent.contentType.toString() == "application/jwt"
                        }
                        encryptionAwareRequestValidator<CredentialRequestTO>(it, issuerMetadataVersion) {
                            assertTrue("Encryption parameters were expected to be sent but was not.") {
                                it.credentialResponseEncryption == null
                            }
                        }
                    },
                ),
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
            }
        }

    @Test
    fun `when issuer specifies encrypted responses, request encryption is required`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            assertFailsWith<MissingRequiredRequestEncryptionSpecification> {
                authorizeRequestForCredentialOffer(
                    credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                    requestEncryptionSpecFactory = { _, _ -> null },
                    responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                    httpClient = mockedKtorHttpClientFactory,
                )
            }
        }

    @Test
    fun `when issuer requires encrypted requests but no request encryption specification is deducted, fail`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_REQUIRED),
            )
            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )
            assertFailsWith<IssuerRequiresEncryptedRequestButEncryptionSpecCannotBeFormulated> {
                authorizeRequestForCredentialOffer(
                    credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                    requestEncryptionSpecFactory = { _, _ -> null },
                    responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                    httpClient = mockedKtorHttpClientFactory,
                )
            }
        }

    @Test
    fun `when issuer supports but not mandates encrypted responses, client can request NON encrypted responses`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                singleIssuanceRequestMocker(
                    responseBuilder = { request ->
                        encryptionAwareResponseDataBuilder(request, issuerMetadataVersion) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "issued_credential")
                                        },
                                    ),
                                    notificationId = "fgh126lbHjtspVbn",
                                ),
                            )
                        }
                    },
                    requestValidator = { request ->
                        encryptionAwareRequestValidator<CredentialRequestTO>(request, issuerMetadataVersion) {
                            assertTrue("Encryption parameters were expected to be sent but was not.") {
                                it.credentialResponseEncryption == null
                            }
                        }
                    },
                ),
            )
            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> null },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, request must be encrypted`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "issued_credential")
                                        },
                                    ),
                                    notificationId = "fgh126lbHjtspVbn",
                                ),
                            )
                        }
                    },
                    requestValidator = {
                        val textContent = it.body as TextContent
                        val contentType = textContent.contentType.toString()
                        assertTrue("Issuer expects encrypted requests. Content-Type header must be 'application/jwt'") {
                            contentType == "application/jwt"
                        }
                        encryptionAwareRequestValidator<CredentialRequestTO>(it, issuerMetadataVersion) { }
                    },
                ),
            )

            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                val (_, outcome) = authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
                assertIs<SubmissionOutcome.Success>(outcome)
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, request must include response encryption material`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_SUPPORTED_NOT_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "issued_credential")
                                        },
                                    ),
                                    notificationId = "fgh126lbHjtspVbn",
                                ),
                            )
                        }
                    },
                    requestValidator = { request ->
                        assertTrue("No Authorization header passed.") {
                            request.headers.contains("Authorization")
                        }
                        assertTrue("Authorization header malformed.") {
                            request.headers["Authorization"]?.contains("Bearer") ?: false
                        }
                        encryptionAwareRequestValidator<CredentialRequestTO>(request, issuerMetadataVersion) {
                            assertTrue("Missing response encryption JWK") {
                                it.credentialResponseEncryption?.jwk != null
                            }
                            assertTrue("Missing response encryption method") {
                                it.credentialResponseEncryption?.encryptionMethod != null
                            }
                        }
                    },
                ),
            )

            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val credentialConfigurationId = issuer.credentialOffer.credentialConfigurationIdentifiers[0]
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(credentialConfigurationId)
                val (_, outcome) = authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
                assertIs<SubmissionOutcome.Success>(outcome)
            }
        }

    @Test
    fun `when issuer mandates encrypted responses, batch response is encrypted and parsable`() =
        runTest {
            val mockedKtorHttpClientFactory = mockedHttpClient(
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_REQUIRED),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, IssuerMetadataVersion.ENCRYPTION_REQUIRED) {
                            Json.encodeToString(
                                CredentialResponseSuccessTO(
                                    credentials = listOf(
                                        buildJsonObject {
                                            put("credential", "${PID_MsoMdoc}_issued_credential")
                                        },
                                    ),
                                ),
                            )
                        }
                    },
                    requestValidator = {},
                ),
            )

            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            val (_, outcome) = with(issuer) {
                authorizedRequest.request(
                    IssuanceRequestPayload.ConfigurationBased(CredentialConfigurationIdentifier(PID_MsoMdoc)),
                    noKeyAttestationJwtProofsSpec(Curve.P_256),
                ).getOrThrow()
            }
            assertIs<SubmissionOutcome.Success>(outcome)
        }

    @Test
    fun `when deferred response is expected to be encrypted but is not, throws InvalidResponseContentType`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            """ { "transaction_id": "1234565768122", "interval": 12345 } """.trimIndent()
                        }
                    },
                ),
                deferredIssuanceRequestMocker(
                    responseBuilder = { defaultIssuanceResponseDataBuilder(true) },
                ),
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                    CredentialConfigurationIdentifier(PID_SdJwtVC),
                )
                val (newAuthorizedRequest, outcome) =
                    authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
                assertIs<SubmissionOutcome.Deferred>(outcome)

                assertFailsWith<CredentialIssuanceError.InvalidResponseContentType>(
                    block = {
                        newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId).getOrThrow()
                    },
                )
            }
        }

    @Test
    fun `when encrypted deferred response is mandated, request must include credential_response_encryption parameters`() =
        runTest {
            val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_REQUIRED
            val mockedKtorHttpClientFactory = mockedHttpClient(
                credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion),
                authServerWellKnownMocker(),
                parPostMocker(),
                tokenPostMocker(),
                nonceEndpointMocker(),
                singleIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            """ { "transaction_id": "1234565768122", "interval": 12345 } """.trimIndent()
                        }
                    },
                ),
                deferredIssuanceRequestMocker(
                    responseBuilder = {
                        encryptionAwareResponseDataBuilder(it, issuerMetadataVersion) {
                            """ { "credentials": [{ "credential": "credential_content" }] }""".trimIndent()
                        }
                    },
                    requestValidator = { request ->
                        encryptionAwareRequestValidator<DeferredRequestTO>(request, issuerMetadataVersion) {
                            assertTrue("Encryption parameters expected to be sent but was not") {
                                it.credentialResponseEncryption != null
                            }
                            assertTrue("Wrong encryption method") {
                                it.credentialResponseEncryption?.encryptionMethod == EncryptionMethod.A128CBC_HS256.name
                            }
                        }
                    },
                ),
            )

            val issuanceResponseEncryptionSpec = EncryptionSpec(
                jwk = randomRSAEncryptionKey(2048),
                encryptionMethod = EncryptionMethod.A128CBC_HS256,
            )

            val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
                credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                responseEncryptionSpecFactory = { _, _ -> issuanceResponseEncryptionSpec },
                httpClient = mockedKtorHttpClientFactory,
            )

            with(issuer) {
                val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                    CredentialConfigurationIdentifier(PID_SdJwtVC),
                )
                val (newAuthorizedRequest, outcome) =
                    authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
                assertIs<SubmissionOutcome.Deferred>(outcome)

                val (_, deferredOutcome) = newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId).getOrThrow()
                assertIs<DeferredCredentialQueryOutcome.Issued>(deferredOutcome)
            }
        }

    @Test
    fun `when issuer metadata mandate encrypted responses, deferred responses must be encrypted`() = runTest {
        val responseEncryption = EncryptionSpec(
            jwk = randomRSAEncryptionKey(2048),
            encryptionMethod = EncryptionMethod.A128CBC_HS256,
        )
        val mockedKtorHttpClientFactory = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.ENCRYPTION_REQUIRED),
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            singleIssuanceRequestMocker(
                responseBuilder = {
                    encryptionAwareResponseDataBuilder(it, IssuerMetadataVersion.ENCRYPTION_REQUIRED) {
                        """ { "transaction_id": "1234565768122", "interval": 12345 } """.trimIndent()
                    }
                },
            ),
            deferredIssuanceRequestMocker(
                responseBuilder = {
                    val responseJson = """
                            {                     
                              "credentials": [{ "credential": "credential_content" }]
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

        val (authorizedRequest, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
            responseEncryptionSpecFactory = { _, _ -> responseEncryption },
            httpClient = mockedKtorHttpClientFactory,
        )

        with(issuer) {
            val requestPayload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(PID_SdJwtVC),
            )
            val (newAuthorizedRequest, outcome) =
                authorizedRequest.request(requestPayload, noKeyAttestationJwtProofsSpec(Curve.P_256)).getOrThrow()
            assertIs<SubmissionOutcome.Deferred>(outcome)

            val (_, deferredOutcome) =
                newAuthorizedRequest.queryForDeferredCredential(outcome.transactionId).getOrThrow()

            assertIs<DeferredCredentialQueryOutcome.Issued>(deferredOutcome)
        }
    }

    @Test
    fun `when metadata response contains four valid and one unknown format, skip it and deserialize everything else`() = runTest {
        val mockedKtorHttpClientFactory = mockedHttpClient(
            authServerWellKnownMocker(),
            parPostMocker(),
            tokenPostMocker(),
            nonceEndpointMocker(),
            credentialIssuerMetadataWellKnownMocker(IssuerMetadataVersion.CONTAINS_DEPRECATED_METHOD),
        )
        val (_, issuer) = authorizeRequestForCredentialOffer(
            credentialOfferStr = CredentialOfferMsoMdoc_NO_GRANTS,
            responseEncryptionSpecFactory = { _, _ -> null },
            httpClient = mockedKtorHttpClientFactory,
        )
        assertTrue("Deserialization did not discard unknown format credential_configurations_supported values") {
            issuer.credentialOffer.credentialIssuerMetadata.credentialConfigurationsSupported.count() == 4
        }
    }

    @Test
    fun randomECEncryptionKey() {
        ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .keyID(UUID.randomUUID().toString())
            .algorithm(JWEAlgorithm.ECDH_ES)
            .issueTime(Date(System.currentTimeMillis()))
            .generate().also { println(it.toPublicJWK()) }
    }
}

fun randomRSAEncryptionKey(size: Int, algorithm: JWEAlgorithm = JWEAlgorithm.RSA_OAEP_256): RSAKey = RSAKeyGenerator(size)
    .keyUse(KeyUse.ENCRYPTION)
    .keyID(UUID.randomUUID().toString())
    .algorithm(algorithm)
    .issueTime(Date(System.currentTimeMillis()))
    .generate()
