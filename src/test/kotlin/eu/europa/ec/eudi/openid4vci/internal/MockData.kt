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

import eu.europa.ec.eudi.openid4vci.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Gets the [CredentialIssuerId] used throughout the tests.
 */
internal fun credentialIssuerId() = CredentialIssuerId("https://credential-issuer.example.com").getOrThrow()

/**
 * Get the URL for fetching the metadata of the Credential Issuer used throughout the tests.
 */
internal fun credentialIssuerMetadataUrl() =
    HttpsUrl("https://credential-issuer.example.com/.well-known/openid-credential-issuer").getOrThrow()

/**
 * Gets the 'UniversityDegree_JWT' scoped credential used throughout the tests.
 */
internal fun universityDegreeJwt() =
    CredentialSupportedObject.W3CVerifiableCredentialSignedJwtCredentialSupportedObject(
        "jwt_vc_json",
        "UniversityDegree_JWT",
        listOf("did:example"),
        listOf("ES256K"),
        listOf("jwt"),
        listOf(
            DisplayObject(
                "University Credential",
                "en-US",
                DisplayObject.LogoObject(
                    "https://exampleuniversity.com/public/logo.png",
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
 * Gets the [CredentialIssuerMetadata] used throughout the tests.
 */
internal fun credentialIssuerMetadata() =
    CredentialIssuerMetadata(
        credentialIssuerId(),
        credentialEndpoint = CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials").getOrThrow(),
        credentialsSupported = listOf(universityDegreeJwt()),
    )
