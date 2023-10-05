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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.CredentialSupported.MsoMdocCredentialCredentialSupported
import eu.europa.ec.eudi.openid4vci.CredentialSupported.W3CVerifiableCredentialCredentialSupported.W3CVerifiableCredentialSignedJwtCredentialSupported
import eu.europa.ec.eudi.openid4vci.CredentialSupported.W3CVerifiableCredentialCredentialSupported.W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported
import io.ktor.http.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.*

/**
 * Gets the [CredentialIssuerId] used throughout the tests.
 */
internal fun credentialIssuerId() = CredentialIssuerId("https://credential-issuer.example.com").getOrThrow()

/**
 * Get the URL for fetching the metadata of the Credential Issuer used throughout the tests.
 */
internal fun credentialIssuerMetadataUrl(credentialIssuerId: CredentialIssuerId = credentialIssuerId()) =
    HttpsUrl(
        URLBuilder(credentialIssuerId.value.value.toString())
            .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
            .buildString(),
    ).getOrThrow()

/**
 * Gets the 'UniversityDegree_JWT' scoped credential used throughout the tests.
 */
internal fun universityDegreeJwt() =
    W3CVerifiableCredentialSignedJwtCredentialSupported(
        "UniversityDegree_JWT",
        listOf(CryptographicBindingMethod.DID("did:example")),
        listOf("ES256K"),
        listOf(ProofType.JWT),
        listOf(
            Display(
                "University Credential",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    HttpsUrl("https://exampleuniversity.com/public/logo.png").getOrThrow(),
                    "a square logo of a university",
                ),
                null,
                "#12107c",
                "#FFFFFF",
            ),
        ),
        JsonObject(
            mapOf(
                "type" to JsonArray(
                    listOf(
                        JsonPrimitive("VerifiableCredential"),
                        JsonPrimitive("UniversityDegreeCredential"),
                    ),
                ),
                "credentialSubject" to JsonObject(
                    mapOf(
                        "given_name" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("Given Name"),
                                                "locale" to JsonPrimitive("en-US"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        "family_name" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("Surname"),
                                                "locale" to JsonPrimitive("en-US"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        "degree" to JsonObject(emptyMap()),
                        "gpa" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("GPA"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        emptyList(),
    )

/**
 * Gets the 'UniversityDegree_LDP_VC' scoped credential used throughout the tests.
 */
internal fun universityDegreeLdpVc() =
    W3CVerifiableCredentialsJsonLdDataIntegrityCredentialSupported(
        "UniversityDegree_LDP_VC",
        listOf(CryptographicBindingMethod.DID("did:example")),
        listOf("Ed25519Signature2018"),
        listOf(ProofType.JWT),
        listOf(
            Display(
                "University Credential",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    HttpsUrl("https://exampleuniversity.com/public/logo.png").getOrThrow(),
                    "a square logo of a university",
                ),
                null,
                "#12107c",
                "#FFFFFF",
            ),
        ),
        listOf(
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
        ),
        listOf(
            "VerifiableCredential_LDP_VC",
            "UniversityDegreeCredential_LDP_VC",
        ),
        JsonObject(
            mapOf(
                "@context" to JsonArray(
                    listOf(
                        JsonPrimitive("https://www.w3.org/2018/credentials/v1"),
                        JsonPrimitive("https://www.w3.org/2018/credentials/examples/v1"),
                    ),
                ),
                "type" to JsonArray(
                    listOf(
                        JsonPrimitive("VerifiableCredential_LDP_VC"),
                        JsonPrimitive("UniversityDegreeCredential_LDP_VC"),
                    ),
                ),
                "credentialSubject" to JsonObject(
                    mapOf(
                        "given_name" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("Given Name"),
                                                "locale" to JsonPrimitive("en-US"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        "family_name" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("Surname"),
                                                "locale" to JsonPrimitive("en-US"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                        "degree" to JsonObject(emptyMap()),
                        "gpa" to JsonObject(
                            mapOf(
                                "display" to JsonArray(
                                    listOf(
                                        JsonObject(
                                            mapOf(
                                                "name" to JsonPrimitive("GPA"),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        emptyList(),
    )

/**
 * Gets the 'mDL' scoped credential used throughout the tests.
 */
internal fun mobileDrivingLicense() =
    MsoMdocCredentialCredentialSupported(
        "mDL",
        listOf(CryptographicBindingMethod.MSO),
        listOf("ES256", "ES384", "ES512"),
        listOf(ProofType.JWT),
        listOf(
            Display(
                "Mobile Driving License",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    HttpsUrl("https://examplestate.com/public/mdl.png").getOrThrow(),
                    "a square figure of a mobile driving license",
                ),
                null,
                "#12107c",
                "#FFFFFF",
            ),
        ),
        "org.iso.18013.5.1.mDL",
        mapOf(
            "org.iso.18013.5.1" to mapOf(
                "given_name" to MsoMdocCredentialCredentialSupported.Claim(
                    display = listOf(
                        MsoMdocCredentialCredentialSupported.Claim.Display(
                            "Given Name",
                            Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "family_name" to MsoMdocCredentialCredentialSupported.Claim(
                    display = listOf(
                        MsoMdocCredentialCredentialSupported.Claim.Display(
                            "Surname",
                            Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "birth_date" to MsoMdocCredentialCredentialSupported.Claim(),
            ),
            "org.iso.18013.5.1.aamva" to mapOf(
                "organ_donor" to MsoMdocCredentialCredentialSupported.Claim(),
            ),
        ),
    )

/**
 * Gets the [CredentialIssuerMetadata] used throughout the tests.
 */
internal fun credentialIssuerMetadata() =
    CredentialIssuerMetadata(
        credentialIssuerId(),
        HttpsUrl("https://credential-issuer.example.com/authorization").getOrThrow(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials").getOrThrow(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials/batch").getOrThrow(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials/deferred").getOrThrow(),
        listOf(JWEAlgorithm.PBES2_HS512_A256KW, JWEAlgorithm.PBES2_HS384_A192KW, JWEAlgorithm.PBES2_HS256_A128KW),
        listOf(EncryptionMethod.XC20P),
        true,
        listOf(universityDegreeJwt(), mobileDrivingLicense(), universityDegreeLdpVc()),
        listOf(CredentialIssuerMetadata.Display("credential-issuer.example.com", "en-US")),
    )
