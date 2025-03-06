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
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.CredentialResponseAsymmetricEncryptionAlgorithmsRequired
import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadataValidationError.InvalidCredentialIssuerId
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.assertDoesNotThrow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class DefaultCredentialIssuerMetadataResolverTest {

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
        val metaData = assertDoesNotThrow { resolver.resolve(credentialIssuerId, IssuerMetadataPolicy.IgnoreSigned).getOrThrow() }
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

        assertTrue("Expected ") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_JWT")
            proofs != null && proofs.all { it.keyAttestationRequirement is KeyAttestationRequirement.NotRequired }
        }

        assertTrue("Expected ") {
            val proofs = credentialConfigs.jwtProofTypeSupported("MobileDrivingLicense_msoMdoc")
            proofs != null && proofs.all { it.keyAttestationRequirement is KeyAttestationRequirement.RequiredNoConstraints }
        }

        assertTrue("Expected ") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_LDP_VC")
            proofs != null && proofs.all { it.keyAttestationRequirement is KeyAttestationRequirement.Required }
        }

        assertTrue("Expected ") {
            val proofs = credentialConfigs.jwtProofTypeSupported("UniversityDegree_JWT_VC_JSON-LD")
            proofs != null && proofs.all { it.keyAttestationRequirement is KeyAttestationRequirement.Required }
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

        val issuerTrust = IssuerTrust.ByPublicKey(
            ECKeyGenerator(Curve.P_256).generate().toPublicJWK(),
        )
        val policy = IssuerMetadataPolicy.RequireSigned(issuerTrust)

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

        val issuerTrust = IssuerTrust.ByPublicKey(
            ECKeyGenerator(Curve.P_256).generate().toPublicJWK(),
        )
        val policy = IssuerMetadataPolicy.PreferSigned(issuerTrust)

        val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
        assertEquals(credentialIssuerMetadata(), metadata)
    }

    @Test
    internal fun `resolution fails when signed metadata is required or optional and present but not signed by a trusted issuer`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_partial.json",
                ),
            )

            val issuerTrust = IssuerTrust.ByPublicKey(
                ECKeyGenerator(Curve.P_256).generate().toPublicJWK(),
            )

            listOf(IssuerMetadataPolicy.RequireSigned(issuerTrust), IssuerMetadataPolicy.PreferSigned(issuerTrust)).forEach { policy ->
                assertFailsWith<CredentialIssuerMetadataError.InvalidSignedMetadata> {
                    resolver.resolve(credentialIssuerId, policy).getOrThrow()
                }
            }
        }

    @Test
    internal fun `resolution succeeds and precedence is given to signed metadata values over plain json elements`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_partial.json",
                ),
            )

            val issuerTrust = IssuerTrust.ByPublicKey(
                ECKey.parse(getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/signed_metadata_jwk.json")).toPublicJWK(),
            )
            val policy = IssuerMetadataPolicy.PreferSigned(issuerTrust)

            val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
            assertEquals(credentialIssuerSignedMetadata(), metadata)
        }

    @Test
    internal fun `resolution fails when signed metadata is required and present but does not contain all required values`() =
        runTest {
            val credentialIssuerId = SampleIssuer.Id

            val resolver = resolver(
                credentialIssuerMetaDataHandler(
                    credentialIssuerId,
                    "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_partial.json",
                ),
            )

            val issuerTrust = IssuerTrust.ByPublicKey(
                ECKey.parse(getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/signed_metadata_jwk.json")).toPublicJWK(),
            )
            val policy = IssuerMetadataPolicy.RequireSigned(issuerTrust)

            assertFailsWith<InvalidCredentialIssuerId> {
                resolver.resolve(credentialIssuerId, policy).getOrThrow()
            }
        }

    @Test
    internal fun `resolution succeeds when signed metadata is required present and contains all values`() = runTest {
        val credentialIssuerId = SampleIssuer.Id

        val resolver = resolver(
            credentialIssuerMetaDataHandler(
                credentialIssuerId,
                "eu/europa/ec/eudi/openid4vci/internal/credential_issuer_metadata_with_signed_full.json",
            ),
        )

        val issuerTrust = IssuerTrust.ByPublicKey(
            ECKey.parse(getResourceAsText("eu/europa/ec/eudi/openid4vci/internal/signed_metadata_jwk.json")).toPublicJWK(),
        )
        val policy = IssuerMetadataPolicy.RequireSigned(issuerTrust)

        val metadata = assertDoesNotThrow { resolver.resolve(credentialIssuerId, policy).getOrThrow() }
        assertEquals(credentialIssuerSignedMetadata(), metadata)
    }
}

private fun Map<CredentialConfigurationIdentifier, CredentialConfiguration>.jwtProofTypeSupported(
    credentialConfigId: String,
): List<ProofTypeMeta.Jwt>? =
    this[CredentialConfigurationIdentifier(credentialConfigId)]?.proofTypesSupported?.values?.filterIsInstance<ProofTypeMeta.Jwt>()

private fun resolver(request: RequestMocker, expectSuccessOnly: Boolean = false) =
    CredentialIssuerMetadataResolver(
        mockedKtorHttpClientFactory(request, expectSuccessOnly = expectSuccessOnly),
    )
