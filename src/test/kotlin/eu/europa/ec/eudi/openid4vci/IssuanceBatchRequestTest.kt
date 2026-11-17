/*
 * Copyright (c) 2023-2026 European Commission
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
import eu.europa.ec.eudi.openid4vci.CertOps.toX509Certificate
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.jwtProofWithKeyAttestationSpec
import eu.europa.ec.eudi.openid4vci.CryptoGenerator.jwtProofsWithoutKeyAttestation
import eu.europa.ec.eudi.openid4vci.internal.fromNimbusEcKey
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.x500.X500Name
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import kotlin.test.*

class IssuanceBatchRequestTest {
    @Nested
    @DisplayName("JWT Proof with Key Attestation")
    inner class JwtProofWithKeyAttestation {
        @Test
        fun `successful batch issuance`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.ENCRYPTION_REQUIRED
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                        singleIssuanceRequestMocker(
                            responseBuilder = encryptionAwareSuccessCredentialResponseResponseDataBuilder(issuerMetadataVersion, 3),
                            requestValidator = encryptionAwareJwtProofWithKeyAttestationRequestValidator(issuerMetadataVersion, 3),
                        ),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        credentialOfferStr = CredentialOfferMixedDocTypes_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_MSO_MDOC),
                    )
                val (_, outcome) =
                    with(issuer) {
                        authorizedRequest.request(request, jwtProofWithKeyAttestationSpec(attestedKeysCount = 3)).getOrThrow()
                    }
                when (outcome) {
                    is SubmissionOutcome.Failed -> {
                        fail(outcome.error.message)
                    }

                    is SubmissionOutcome.Deferred -> {
                        fail("Got deferred")
                    }

                    is SubmissionOutcome.Success -> {
                        outcome.credentials.forEach { assertIs<IssuedCredential>(it) }
                    }
                }
            }
    }

    @Nested
    @DisplayName("JWT Proofs without Key Attestation")
    inner class JwtProofsWithoutKeyAttestation {
        @Test
        fun `successful batch issuance`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.ONLY_JWT_PROOFS_WITHOUT_KEY_ATTESTATION_SUPPORTED
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                        singleIssuanceRequestMocker(
                            responseBuilder = encryptionAwareSuccessCredentialResponseResponseDataBuilder(issuerMetadataVersion, 3),
                            requestValidator = encryptionAwareJwtProofsWithoutKeyAttestationRequestValidator(issuerMetadataVersion, 3),
                        ),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfigurationOnlyPlainJwtProofs,
                        credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SD_JWT_VC),
                    )
                val (_, outcome) =
                    with(issuer) {
                        authorizedRequest.request(request, jwtProofsWithoutKeyAttestation(keysNo = 3)).getOrThrow()
                    }
                val issuedCredentials = assertIs<SubmissionOutcome.Success>(outcome).credentials
                assertEquals(3, issuedCredentials.size, "Expected 3 Credentials to be issued")
            }

        @Test
        fun `fails when sending more proofs that allowed batch size`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.ONLY_JWT_PROOFS_WITHOUT_KEY_ATTESTATION_SUPPORTED
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfigurationOnlyPlainJwtProofs,
                        credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SD_JWT_VC),
                    )
                val error =
                    assertFailsWith<CredentialIssuanceError.IssuerBatchSizeLimitExceeded> {
                        with(issuer) {
                            authorizedRequest.request(request, jwtProofsWithoutKeyAttestation(keysNo = 4)).getOrThrow()
                        }
                    }
                assertEquals(3, error.batchSize)
            }

        @Test
        fun `fails when the batch signer uses the same key more than once`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.ONLY_JWT_PROOFS_WITHOUT_KEY_ATTESTATION_SUPPORTED
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfigurationOnlyPlainJwtProofs,
                        credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )
                val oneKey = jwtProofsWithoutKeyAttestation(keysNo = 1).proofSigner
                val sameKeyThreeTimes =
                    object : BatchSigner<JwtBindingKey> {
                        override val javaAlgorithm: String = oneKey.javaAlgorithm

                        override suspend fun authenticate(): BatchSignOperation<JwtBindingKey> {
                            val operation = oneKey.authenticate().operations.single()
                            return BatchSignOperation(List(3) { operation })
                        }

                        override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) = Unit
                    }

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SD_JWT_VC),
                    )
                assertFailsWith<CredentialIssuanceError.ProofGenerationError.DuplicateBindingKeys> {
                    with(issuer) {
                        authorizedRequest
                            .request(request, ProofSpecification.JwtProofsWithoutKeyAttestation(sameKeyThreeTimes))
                            .getOrThrow()
                    }
                }
            }

        @Test
        fun `fails when the batch signer gives the same key as a JWK and as a certificate`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.ONLY_JWT_PROOFS_WITHOUT_KEY_ATTESTATION_SUPPORTED
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfigurationOnlyPlainJwtProofs,
                        credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )
                val key = CryptoGenerator.randomECSigningKey(Curve.P_256)
                val certificate =
                    CertOps.createTrustAnchor(key.toKeyPair(), "SHA256withECDSA", X500Name("CN=Binding Key")).toX509Certificate()
                val asJwk = Signer.fromNimbusEcKey(key, JwtBindingKey.Jwk(key.toPublicJWK()), null, null)
                val asCertificate = Signer.fromNimbusEcKey(key, JwtBindingKey.X509(listOf(certificate)), null, null)
                val sameKeyTwoForms =
                    object : BatchSigner<JwtBindingKey> {
                        override val javaAlgorithm: String = asJwk.javaAlgorithm

                        override suspend fun authenticate(): BatchSignOperation<JwtBindingKey> =
                            BatchSignOperation(listOf(asJwk.acquire(), asCertificate.acquire()))

                        override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) = Unit
                    }

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SD_JWT_VC),
                    )
                assertFailsWith<CredentialIssuanceError.ProofGenerationError.DuplicateBindingKeys> {
                    with(issuer) {
                        authorizedRequest
                            .request(request, ProofSpecification.JwtProofsWithoutKeyAttestation(sameKeyTwoForms))
                            .getOrThrow()
                    }
                }
            }

        @Test
        fun `fails when issuer does not support batch credential issuance`() =
            runTest {
                val issuerMetadataVersion = IssuerMetadataVersion.NO_BATCH
                val mockedKtorHttpClientFactory =
                    mockedHttpClient(
                        credentialIssuerMetadataWellKnownMocker(issuerMetadataVersion = issuerMetadataVersion),
                        authServerWellKnownMocker(),
                        parPostMocker(),
                        tokenPostMocker(),
                        nonceEndpointMocker(),
                    )
                val (authorizedRequest, issuer) =
                    authorizeRequestForCredentialOffer(
                        config = OpenId4VCIConfigurationOnlyPlainJwtProofs,
                        credentialOfferStr = CredentialOfferWithSdJwtVc_NO_GRANTS,
                        httpClient = mockedKtorHttpClientFactory,
                    )

                val request =
                    IssuanceRequestPayload.ConfigurationBased(
                        CredentialConfigurationIdentifier(PID_SD_JWT_VC),
                    )
                assertFailsWith<CredentialIssuanceError.IssuerDoesNotSupportBatchIssuance> {
                    with(issuer) {
                        authorizedRequest.request(request, jwtProofsWithoutKeyAttestation(keysNo = 3)).getOrThrow()
                    }
                }
            }
    }
}
