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

import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.*
import eu.europa.ec.eudi.openid4vci.internal.wellKnown
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.*
import kotlin.time.Duration.Companion.seconds

internal class DefaultCredentialIssuerMetadataResolverTest {

    val trustAll = CertificateChainTrust { _ -> true }
    val trustNone = CertificateChainTrust { _ -> false }

    @Test
    internal fun `fails when metadata cannot be fetched`() = runTest {
        val resolver = resolver(
            RequestMocker(
                requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
                responseBuilder = {
                    respond(
                        content = "Not Found",
                        status = HttpStatusCode.NotFound,
                        headers = headersOf(
                            HttpHeaders.ContentType to listOf("application/json"),
                        ),
                    )
                },
                requestValidator = {
                    assertEquals(
                        SampleIssuer.WellKnownUrl.value.toURI(),
                        it.url.toURI(),
                    )
                },
            ),
            expectSuccessOnly = true,
        )
        assertFailsWith<UnableToFetchCredentialIssuerMetadata> {
            resolver.resolve(SampleIssuer.Id, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
    }

    @Test
    internal fun `fails when metadata cannot be parsed`() = runTest {
        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                SampleIssuer.Id,
                "eu/europa/ec/eudi/openid4vci/internal/invalid_credential_issuer_metadata.json",
            ),
        )
        assertFailsWith<NonParseableCredentialIssuerMetadata> {
            resolver.resolve(SampleIssuer.Id, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
    }

    @Test
    internal fun `fails with unexpected credential issuer id`() = runTest {
        val credentialIssuerId = CredentialIssuerId("https://issuer.com").getOrThrow()
        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )

        assertFailsWith<InvalidCredentialIssuerId> {
            resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
    }

    @Test
    internal fun `fails when response encryption algorithms are not asymmetric`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_asymmetric_algs.json",
            ),

        )
        assertFailsWith<CredentialResponseAsymmetricEncryptionAlgorithmsRequired> {
            resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
    }

    @Test
    internal fun `resolution success`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )
        val metaData =
            assertDoesNotThrow { resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow() }
        assertEquals(credentialIssuerMetadata(), metaData)
    }

    @Test
    internal fun `valid key attestation requirements`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )
        val credentialConfigs = assertDoesNotThrow {
            resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }.credentialConfigurationsSupported

        assertTrue("Unexpected proofs for UniversityDegree_JWT") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_JWT")
            proofs != null && proofs.all { it.keyAttestationRequirement == KeyAttestationRequirement(null, null, null) }
        }

        assertTrue("Unexpected proofs for MobileDrivingLicense_msoMdoc") {
            val proofs = credentialConfigs.jwtProofTypeSupported("MobileDrivingLicense_msoMdoc")
            proofs != null && proofs.all {
                val proof = it.keyAttestationRequirement
                proof == KeyAttestationRequirement(
                    keyStorage = listOf(AttackPotentialResistance.Iso18045High),
                    userAuthentication = listOf(AttackPotentialResistance.Iso18045High),
                    null,
                )
            }
        }

        assertTrue("Unexpected proofs for UniversityDegree_LDP_VC") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_LDP_VC")
            proofs != null && proofs.all {
                val proof = it.keyAttestationRequirement
                proof == KeyAttestationRequirement(
                    keyStorage = listOf(AttackPotentialResistance.Iso18045High, AttackPotentialResistance.Iso18045EnhancedBasic),
                    userAuthentication = null,
                    null,
                )
            }
        }

        assertTrue("Unexpected proofs for UniversityDegree_JWT_VC_JSON-LD") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_JWT_VC_JSON-LD")
            proofs != null && proofs.all {
                val proof = it.keyAttestationRequirement
                proof == KeyAttestationRequirement(
                    keyStorage = listOf(AttackPotentialResistance.Iso18045High, AttackPotentialResistance.Iso18045EnhancedBasic),
                    userAuthentication = listOf(AttackPotentialResistance.Iso18045High, AttackPotentialResistance.Iso18045EnhancedBasic),
                    preferredKeyStorageStatusPeriod = null,
                )
            }
        }
    }

    @Test
    internal fun `resolution fails when signed metadata is required but not present`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )

        val policy = IssuerMetadataPolicy.RequireSigned(trustAll)

        assertFailsWith<CredentialIssuerMetadataError.MissingSignedMetadata> {
            resolver.resolve(credentialIssuerId, policy).getOrThrow()
        }
    }

    @Test
    internal fun `resolution succeeds when signed metadata is optional and not present`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_valid.json",
            ),
        )

        val policy = IssuerMetadataPolicy.PreferSigned(trustAll)

        val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
        assertEquals(credentialIssuerMetadata(), metadata)
    }

    @Test
    internal fun `resolution fails when signed metadata are signed by expected issuer but 'typ' is missing`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            listOf(
                IssuerMetadataPolicy.RequireSigned(trustAll),
                IssuerMetadataPolicy.PreferSigned(trustAll),
            ).forEach { policy ->
                val resolver = resolver(
                    credentialIssuerMetaDataHandler(
                        credentialIssuerId,
                        "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_invalid.txt",
                        listOf("application/jwt"),
                    ),
                )

                assertFailsWith<CredentialIssuerMetadataError.InvalidSignedMetadata> {
                    resolver.resolve(credentialIssuerId, policy).getOrThrow()
                }
            }
        }

    @Test
    internal fun `resolution fails when signed metadata is required or optional and present but not signed by a trusted issuer`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            listOf(
                IssuerMetadataPolicy.RequireSigned(trustNone),
                IssuerMetadataPolicy.PreferSigned(trustNone),
            ).forEach { policy ->
                val resolver = resolver(
                    credentialIssuerMetaDataHandler(
                        credentialIssuerId,
                        "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_full.txt",
                        listOf("application/jwt"),
                    ),
                )

                assertFailsWith<CredentialIssuerMetadataError.InvalidSignedMetadata> {
                    resolver.resolve(credentialIssuerId, policy).getOrThrow()
                }
            }
        }

    @Test
    internal fun `resolution fails when signed metadata is required and present but does not contain all required values`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_partial.txt",
                    listOf("application/jwt"),
                ),
            )

            val policy = IssuerMetadataPolicy.RequireSigned(trustAll)

            assertFailsWith<InvalidCredentialIssuerId> {
                resolver.resolve(credentialIssuerId, policy).getOrThrow()
            }
        }

    @Test
    internal fun `resolution fails when response encryption params included but no request encryption params included`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_request_encryption.json",
                ),
            )

            val policy = IssuerMetadataPolicy.IgnoreSigned

            assertFailsWith<CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists> {
                resolver.resolve(credentialIssuerId, policy).getOrThrow()
            }
        }

    @Test
    internal fun `resolution succeeds when no response encryption params included but request encryption params included`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_no_response_encryption.json",
                ),
            )

            val policy = IssuerMetadataPolicy.IgnoreSigned

            val issuerMetadata = credentialIssuerMetadata().copy(
                credentialResponseEncryption = CredentialResponseEncryption.NotSupported,
                preferredClientStatusPeriod = null,
            )

            val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
            assertEquals(issuerMetadata, metadata)
        }

    @Test
    internal fun `resolution succeeds when signed metadata is required present and contains all values`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_full.txt",
                listOf("application/jwt"),
            ),
        )

        val policy = IssuerMetadataPolicy.RequireSigned(trustAll)

        val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
        assertEquals(credentialIssuerSignedMetadata(), metadata)
    }

    @Test
    internal fun `well-known path segment is appended always between the host component and the path component, if any`() = runTest {
        var id = CredentialIssuerId("https://issuer.example.com").getOrThrow()
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer", id.wellKnown().toString())

        id = CredentialIssuerId("https://issuer.example.com/tenant").getOrThrow()
        assertEquals("https://issuer.example.com/.well-known/openid-credential-issuer/tenant", id.wellKnown().toString())
    }

    @Test
    internal fun `resolution succeeds with credential reuse policy`() = runTest {
        suspend fun test(resource: String) {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    resource,
                ),
            )

            val metaData = resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()

            val pidMsoMdoc = assertNotNull(metaData.credentialConfigurationsSupported[CredentialConfigurationIdentifier("PID_msoMdoc")])

            val msoMdocPolicy = assertIs<CredentialReusePolicy.EUDI>(pidMsoMdoc.credentialMetadata?.credentialReusePolicy)
            assertEquals(3, msoMdocPolicy.options.size)
            assertNotNull(msoMdocPolicy.options.firstOrNull { it is EudiReusePolicy.LimitedTime })

            val msoMdocRotatingBatch = assertNotNull(msoMdocPolicy.options.firstOrNull { it is EudiReusePolicy.RotatingBatch })
            assertEquals(5, msoMdocRotatingBatch.batchSize)
            assertEquals(655433.seconds, msoMdocRotatingBatch.reissueTriggerLifetimeLeft)

            val msoMdocOption = assertNotNull(msoMdocPolicy.options.firstOrNull { it is EudiReusePolicy.PerRelyingParty })
            assertEquals(5, msoMdocOption.batchSize)
            assertEquals(655433.seconds, msoMdocOption.reissueTriggerLifetimeLeft)

            val pidSdJwt = assertNotNull(metaData.credentialConfigurationsSupported[CredentialConfigurationIdentifier("PID_SdJwtVc")])

            val sdJwtPolicy = assertIs<CredentialReusePolicy.EUDI>(pidSdJwt.credentialMetadata?.credentialReusePolicy)
            assertEquals(3, sdJwtPolicy.options.size)
            assertNotNull(sdJwtPolicy.options.firstOrNull { it is EudiReusePolicy.LimitedTime })

            val sdJwtRotatingBatch = assertNotNull(sdJwtPolicy.options.firstOrNull { it is EudiReusePolicy.RotatingBatch })
            assertEquals(40, sdJwtRotatingBatch.batchSize)
            assertEquals(655433.seconds, sdJwtRotatingBatch.reissueTriggerLifetimeLeft)

            val sdJwtPerRelyingParty = assertNotNull(sdJwtPolicy.options.firstOrNull { it is EudiReusePolicy.PerRelyingParty })
            assertEquals(40, sdJwtPerRelyingParty.batchSize)
            assertEquals(10, sdJwtPerRelyingParty.reissueTriggerUnused)
            assertEquals(655433.seconds, sdJwtPerRelyingParty.reissueTriggerLifetimeLeft)
        }

        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_compact.json")
        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_expanded.json")
    }

    @Test
    internal fun `resolution fails with credential reuse policy both once only and limited time`() = runTest {
        suspend fun test(resource: String) {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    resource,
                ),
            )

            val error =
                assertFailsWith<InvalidCredentialsSupported> {
                    resolver.resolve(
                        credentialIssuerId,
                        IssuerMetadataPolicy.IgnoreSigned,
                    ).getOrThrow()
                }
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals("details must contain exactly one base method: once_only or limited_time", cause.message)
        }

        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_both_once_only_limited_time_compact.json")
        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_both_once_only_limited_time_expanded.json")
    }

    @Test
    internal fun `resolution fails with duplicate credential reuse policies`() = runTest {
        suspend fun test(resource: String) {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    resource,
                ),
            )

            val error =
                assertFailsWith<InvalidCredentialsSupported> {
                    resolver.resolve(
                        credentialIssuerId,
                        IssuerMetadataPolicy.IgnoreSigned,
                    ).getOrThrow()
                }
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals("When multiple policy options are defined, each option type must be unique", cause.message)
        }

        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_duplicates_compact.json")
        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_duplicates_expanded.json")
    }

    @Test
    internal fun `resolution fails with duplicate details in credential reuse policies`() = runTest {
        suspend fun test(resource: String) {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    resource,
                ),
            )

            val error =
                assertFailsWith<InvalidCredentialsSupported> {
                    resolver.resolve(
                        credentialIssuerId,
                        IssuerMetadataPolicy.IgnoreSigned,
                    ).getOrThrow()
                }
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals("details must not contain duplicate values", cause.message)
        }

        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_duplicate_details_compact.json")
        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_duplicate_details_expanded.json")
    }

    @Test
    internal fun `resolution fails when no base credential reuse policy is present`() = runTest {
        suspend fun test(resource: String) {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    resource,
                ),
            )

            val error =
                assertFailsWith<InvalidCredentialsSupported> {
                    resolver.resolve(
                        credentialIssuerId,
                        IssuerMetadataPolicy.IgnoreSigned,
                    ).getOrThrow()
                }
            val cause = assertIs<IllegalArgumentException>(error.cause)
            assertEquals("details must contain exactly one base method: once_only or limited_time", cause.message)
        }

        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_only_rotating_batch.json")
        test("eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_reuse_policy_only_per_relying_party.json")
    }

    @Test
    internal fun `resolution succeeds with unknown credential reuse policy`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_unknown_reuse_policy.json",
            ),
        )
        val metaData =
            assertDoesNotThrow { resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow() }

        val pidMsoMdoc = metaData.credentialConfigurationsSupported[CredentialConfigurationIdentifier("PID_msoMdoc")]
        val msoMdocPolicy = pidMsoMdoc?.credentialMetadata?.credentialReusePolicy
        assertEquals(CredentialReusePolicy.None, msoMdocPolicy)
    }

    @Test
    internal fun `resolution succeeds for signed metadata that use x5c`() = runTest {
        val credentialIssuerId = SampleIssuer.Id
        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/openid-credential-issuer-signed-metadata-x5c.jwt",
                listOf("application/jwt"),
            ),
        )
        val policy = IssuerMetadataPolicy.RequireSigned(trustAll)
        assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
    }

    @Test
    internal fun `resolution fails when preferred_client_status_period is negative`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_negative_preferred_client_status_period.json",
            ),
        )
        val exception = assertFailsWith<InvalidPreferredClientStatusPeriod> {
            resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("Duration must be positive", cause.message)
    }

    @Test
    internal fun `resolution fails when preferred_client_status_period is zero`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_zero_preferred_client_status_period.json",
            ),
        )
        val exception = assertFailsWith<InvalidPreferredClientStatusPeriod> {
            resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow()
        }
        val cause = assertIs<IllegalArgumentException>(exception.cause)
        assertEquals("Duration must be positive", cause.message)
    }
}

private fun Map<CredentialConfigurationIdentifier, CredentialConfiguration>.jwtProofTypeSupported(
    credentialConfigId: String,
): List<ProofTypeMeta.Jwt>? =
    this[CredentialConfigurationIdentifier(credentialConfigId)]?.proofTypesSupported?.values?.filterIsInstance<ProofTypeMeta.Jwt>()

private fun resolver(request: RequestMocker, expectSuccessOnly: Boolean = false) =
    CredentialIssuerMetadataResolver(
        mockedHttpClient(request, expectSuccessOnly = expectSuccessOnly),
    )
