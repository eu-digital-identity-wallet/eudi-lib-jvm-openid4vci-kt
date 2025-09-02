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

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.ResponseMode
import com.nimbusds.oauth2.sdk.ResponseType
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerEndpointMetadata
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.ciba.BackChannelTokenDeliveryMode
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod
import eu.europa.ec.eudi.openid4vci.internal.wellKnownUrl
import io.ktor.http.*
import java.net.URI
import java.util.*

object SampleIssuer {
    val Id: CredentialIssuerId = CredentialIssuerId("https://credential-issuer.example.com").getOrThrow()
    val WellKnownUrl = Id.metaDataUrl()
}

object SampleAuthServer {
    val Url = HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()
    val OAuthWellKnownUrl = oauthAuthorizationServerMetadataUrl(Url)
}

/**
 * Get the URL for fetching the metadata of the OAuth Authorization Server used throughout the tests.
 */
internal fun oauthAuthorizationServerMetadataUrl(authorizationServerIssuer: HttpsUrl) = HttpsUrl(
    authorizationServerIssuer.wellKnownUrl("/.well-known/oauth-authorization-server").toString(),
).getOrThrow()

/**
 * Get the URL for fetching the metadata of the Credential Issuer used throughout the tests.
 */
internal fun CredentialIssuerId.metaDataUrl() = HttpsUrl(
    URLBuilder(toString()).appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false).buildString(),
).getOrThrow()

/**
 * Gets the 'UniversityDegree_JWT' scoped credential used throughout the tests.
 */
internal fun universityDegreeJwt() = W3CSignedJwtCredential(
    "UniversityDegree_JWT",
    listOf(CryptographicBindingMethod.DID("did:example")),
    listOf("ES256K"),
    ProofTypesSupported(
        setOf(
            ProofTypeMeta.Jwt(
                listOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
                KeyAttestationRequirement.NotRequired,
            ),
        ),
    ),
    CredentialMetadata(
        listOf(
            Display(
                "University Credential",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    URI.create("https://exampleuniversity.com/public/logo.png"),
                    "a square logo of a university",
                ),
                null,
                "#12107c",
                URI.create("https://examplestate.com/public/background.png"),
                "#FFFFFF",
            ),
        ),
        listOf(
            Claim(
                path = ClaimPath.claim("given_name"),
                display = listOf(
                    Claim.Display("Given Name", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(
                path = ClaimPath.claim("family_name"),
                display = listOf(
                    Claim.Display("Surname", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(path = ClaimPath.claim("degree")),
            Claim(
                path = ClaimPath.claim("gpa"),
                display = listOf(
                    Claim.Display("name", Locale.forLanguageTag("GPA")),
                ),
            ),
        ),
    ),
    W3CSignedJwtCredential.CredentialDefinition(
        listOf("VerifiableCredential", "UniversityDegreeCredential"),
    ),
)

/**
 * Gets the 'UniversityDegree_LDP_VC' scoped credential used throughout the tests.
 */
internal fun universityDegreeLdpVc() = W3CJsonLdDataIntegrityCredential(
    "UniversityDegree_LDP_VC",
    listOf(CryptographicBindingMethod.DID("did:example")),
    listOf("Ed25519Signature2018"),
    ProofTypesSupported(
        setOf(
            ProofTypeMeta.Jwt(
                listOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
                KeyAttestationRequirement.Required(
                    listOf("iso_18045_high", "iso_18045_enhanced-basic"),
                    null,
                ),
            ),
        ),
    ),
    CredentialMetadata(
        listOf(
            Display(
                "University Credential",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    URI.create("https://exampleuniversity.com/public/logo.png"),
                    "a square logo of a university",
                ),
                null,
                "#12107c",
                null,
                "#FFFFFF",
            ),
        ),
        listOf(
            Claim(
                path = ClaimPath.claim("given_name"),
                display = listOf(
                    Claim.Display("Given Name", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(
                path = ClaimPath.claim("family_name"),
                display = listOf(
                    Claim.Display("Surname", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(path = ClaimPath.claim("degree")),
            Claim(
                path = ClaimPath.claim("gpa"),
                display = listOf(
                    Claim.Display("name", Locale.forLanguageTag("GPA")),
                ),
            ),
        ),
    ),
    W3CJsonLdCredentialDefinition(
        listOf(
            URI("https://www.w3.org/2018/credentials/v1").toURL(),
            URI("https://www.w3.org/2018/credentials/examples/v1").toURL(),
        ),
        listOf("VerifiableCredential_LDP_VC", "UniversityDegreeCredential_LDP_VC"),
    ),
)

internal fun universityDegreeJwtVcJsonLD() = W3CJsonLdSignedJwtCredential(
    "UniversityDegree_JWT_VC_JSON-LD",
    listOf(CryptographicBindingMethod.DID("did:example")),
    listOf("Ed25519Signature2018"),
    ProofTypesSupported(
        setOf(
            ProofTypeMeta.Jwt(
                listOf(JWSAlgorithm.RS256, JWSAlgorithm.ES256),
                KeyAttestationRequirement.Required(
                    listOf("iso_18045_high", "iso_18045_enhanced-basic"),
                    listOf("iso_18045_high", "iso_18045_enhanced-basic"),
                ),
            ),
        ),
    ),
    CredentialMetadata(
        listOf(
            Display(
                "University Credential",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    URI.create("https://exampleuniversity.com/public/logo.png"),
                    "a square logo of a university",
                ),
                null,
                "#12107c",
                null,
                "#FFFFFF",
            ),
        ),
        listOf(
            Claim(
                path = ClaimPath.claim("given_name"),
                display = listOf(
                    Claim.Display("Given Name", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(
                path = ClaimPath.claim("family_name"),
                display = listOf(
                    Claim.Display("Surname", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(path = ClaimPath.claim("degree")),
            Claim(
                path = ClaimPath.claim("gpa"),
                display = listOf(
                    Claim.Display("name", Locale.forLanguageTag("GPA")),
                ),
            ),
        ),
    ),
    W3CJsonLdCredentialDefinition(
        listOf(
            URI("https://www.w3.org/2018/credentials/v1").toURL(),
            URI("https://www.w3.org/2018/credentials/examples/v1").toURL(),
        ),
        listOf("VerifiableCredential_JWT_VC_JSON-LD", "UniversityDegreeCredential_JWT_VC_JSON-LD"),
    ),
)

/**
 * Gets the 'mDL' scoped credential used throughout the tests.
 */
internal fun mobileDrivingLicense() = MsoMdocCredential(
    "MobileDrivingLicense_msoMdoc",
    emptyList(),
    listOf("ES256", "ES384", "ES512"),
    emptyList(),
    emptyList(),
    null,
    ProofTypesSupported.Empty,
    CredentialMetadata(
        listOf(
            Display(
                "Mobile Driving License",
                Locale.forLanguageTag("en-US"),
                Display.Logo(
                    URI.create("https://examplestate.com/public/mdl.png"),
                    "a square figure of a mobile driving license",
                ),
                null,
                "#12107c",
                URI.create("https://examplestate.com/public/background.png"),
                "#FFFFFF",
            ),
        ),

        listOf(
            Claim(
                path = ClaimPath.claim("org.iso.18013.5.1").claim("given_name"),
                display = listOf(
                    Claim.Display("Given Name", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(
                path = ClaimPath.claim("org.iso.18013.5.1").claim("family_name"),
                display = listOf(
                    Claim.Display("Surname", Locale.forLanguageTag("en-US")),
                ),
            ),
            Claim(
                path = ClaimPath.claim("org.iso.18013.5.1").claim("birth_date"),
            ),
            Claim(
                path = ClaimPath.claim("org.iso.18013.5.1.aamva").claim("organ_donor"),
            ),
        ),
    ),
    "org.iso.18013.5.1.mDL",
)

/**
 * Gets the [CredentialIssuerMetadata] used throughout the tests.
 */
internal fun credentialIssuerMetadata() = CredentialIssuerMetadata(
    SampleIssuer.Id,
    listOf(SampleAuthServer.Url),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/nonce").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials/deferred").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/notification").getOrThrow(),
    CredentialRequestEncryption.Required(
        SupportedRequestEncryptionParameters(
            encryptionKeys = JWKSet.parse(
                """
                    {
                    "keys": [
                        {
                            "kty": "EC",
                          "use": "enc",
                            "crv": "P-256",
                          "alg": "ECDH-ES",
                          "kid": "encKey-0",
                          "x": "TmcsNF6JpWjP85wKfBXKybHaJNowtp6jCuToppDosdw",
                          "y": "egzDuJuSxyypCE0qUoo1oKOnslpaw1Om-flQ4knafas",
                          "iat": 1755352588
                        }
                    ]
                }
                """,
            ),
            encryptionMethods = listOf(EncryptionMethod.XC20P),
            compressionAlgorithms = listOf(CompressionAlgorithm.DEF),
        ),
    ),
    CredentialResponseEncryption.Required(
        SupportedResponseEncryptionParameters(
            listOf(
                JWEAlgorithm.ECDH_ES,
                JWEAlgorithm.ECDH_ES_A128KW,
                JWEAlgorithm.ECDH_ES_A192KW,
                JWEAlgorithm.ECDH_ES_A256KW,
                JWEAlgorithm.RSA_OAEP_256,
                JWEAlgorithm.RSA_OAEP_384,
                JWEAlgorithm.RSA_OAEP_512,
            ),
            listOf(EncryptionMethod.XC20P),
            listOf(CompressionAlgorithm.DEF),
        ),
    ),
    BatchCredentialIssuance.Supported(batchSize = 2),
    mapOf(
        CredentialConfigurationIdentifier("UniversityDegree_JWT") to universityDegreeJwt(),
        CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc") to mobileDrivingLicense(),
        CredentialConfigurationIdentifier("UniversityDegree_LDP_VC") to universityDegreeLdpVc(),
        CredentialConfigurationIdentifier("UniversityDegree_JWT_VC_JSON-LD") to universityDegreeJwtVcJsonLD(),
    ),
    listOf(
        Display(
            name = "credential-issuer.example.com",
            locale = Locale.forLanguageTag("en-US"),
            logo = Display.Logo(URI.create("https://credential-issuer.example.com/logo.png"), "Credential Issuer Logo"),
        ),
    ),
)

/**
 * Gets the [CredentialIssuerMetadata] used throughout the tests when signed metadata are used.
 */
internal fun credentialIssuerSignedMetadata() = CredentialIssuerMetadata(
    SampleIssuer.Id,
    listOf(SampleAuthServer.Url),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/signed/credentials").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/signed/nonce").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/signed/credentials/deferred").getOrThrow(),
    CredentialIssuerEndpoint("https://credential-issuer.example.com/signed/notification").getOrThrow(),
    CredentialRequestEncryption.NotSupported,
    CredentialResponseEncryption.Required(
        SupportedResponseEncryptionParameters(
            listOf(JWEAlgorithm.RSA_OAEP_256),
            listOf(EncryptionMethod.XC20P),
        ),
    ),
    BatchCredentialIssuance.Supported(batchSize = 15),
    mapOf(
        CredentialConfigurationIdentifier("UniversityDegree_JWT") to universityDegreeJwt(),
        CredentialConfigurationIdentifier("MobileDrivingLicense_msoMdoc") to mobileDrivingLicense(),
        CredentialConfigurationIdentifier("UniversityDegree_LDP_VC") to universityDegreeLdpVc(),
        CredentialConfigurationIdentifier("UniversityDegree_JWT_VC_JSON-LD") to universityDegreeJwtVcJsonLD(),
    ),
    listOf(
        Display(
            name = "credential-issuer.example.com",
            locale = Locale.forLanguageTag("en-US"),
            logo = Display.Logo(URI.create("https://credential-issuer.example.com/logo.png"), "Credential Issuer Logo"),
        ),
    ),
)

/**
 * Gets the [OAuth2 Connect Authorization Server metadata][CIAuthorizationServerMetadata] used throughout the tests.
 */
internal fun oauthAuthorizationServerMetadata(): AuthorizationServerMetadata = AuthorizationServerMetadata(
    Issuer(SampleAuthServer.Url.value.toURI()),
).apply {
    val realmBaseUrl = "https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm"
    val protocolBaseUrl = "$realmBaseUrl/protocol/openid-connect"
    authorizationEndpointURI = URI.create("$protocolBaseUrl/auth")
    tokenEndpointURI = URI.create("$protocolBaseUrl/token")
    introspectionEndpointURI = URI.create("$protocolBaseUrl/token/introspect")
    jwkSetURI = URI.create("$protocolBaseUrl/certs")
    grantTypes = listOf(
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:ietf:params:oauth:grant-type:device_code",
        "urn:openid:params:grant-type:ciba",
    ).map { GrantType(it) }
    responseTypes = listOf(
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token",
    ).map { ResponseType(*it.split(" ").toTypedArray()) }
    requestObjectJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none",
    ).map { JWSAlgorithm(it) }
    requestObjectJWEAlgs = listOf(
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5",
    ).map { JWEAlgorithm(it) }
    requestObjectJWEEncs = listOf(
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
    ).map { EncryptionMethod(it) }
    responseModes = listOf(
        "query",
        "fragment",
        "form_post",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
        "jwt",
    ).map { ResponseMode(it) }
    registrationEndpointURI = URI.create("$realmBaseUrl/clients-registrations/openid-connect")
    tokenEndpointAuthMethods = listOf(
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt",
    ).map { ClientAuthenticationMethod(it) }
    tokenEndpointJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    introspectionEndpointAuthMethods = listOf(
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt",
    ).map { ClientAuthenticationMethod(it) }
    introspectionEndpointJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    authorizationJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    authorizationJWEAlgs = listOf(
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5",
    ).map { JWEAlgorithm(it) }
    authorizationJWEEncs = listOf(
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
    ).map { EncryptionMethod(it) }
    scopes = Scope(
        "openid",
        "eu.europa.ec.eudiw.pid_sd-jwt-vc",
        "web-origins",
        "eu.europa.ec.eudiw.pid_mso_mdoc",
        "offline_access",
        "roles",
    )
    setSupportsRequestParam(true)
    setSupportsRequestURIParam(true)
    setRequiresRequestURIRegistration(true)
    codeChallengeMethods = listOf(
        "plain",
        "S256",
    ).map { CodeChallengeMethod.parse(it) }
    setSupportsTLSClientCertificateBoundAccessTokens(true)
    dPoPJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "ES256",
        "RS256",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    revocationEndpointURI = URI.create("$protocolBaseUrl/revoke")
    revocationEndpointAuthMethods = listOf(
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt",
    ).map { ClientAuthenticationMethod(it) }
    revocationEndpointJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    deviceAuthorizationEndpointURI = URI.create("$protocolBaseUrl/auth/device")
    backChannelTokenDeliveryModes = listOf(
        "poll",
        "ping",
    ).map { BackChannelTokenDeliveryMode(it) }
    backChannelAuthenticationEndpointURI = URI.create("$protocolBaseUrl/ext/ciba/auth")
    backChannelAuthenticationRequestJWSAlgs = listOf(
        "PS384",
        "ES384",
        "RS384",
        "ES256",
        "RS256",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
    ).map { JWSAlgorithm(it) }
    requiresPushedAuthorizationRequests(false)
    pushedAuthorizationRequestEndpointURI = URI.create("$protocolBaseUrl/ext/par/request")
    mtlsEndpointAliases = AuthorizationServerEndpointMetadata().apply {
        tokenEndpointURI = URI.create("$protocolBaseUrl/token")
        revocationEndpointURI = URI.create("$protocolBaseUrl/revoke")
        introspectionEndpointURI = URI.create("$protocolBaseUrl/token/introspect")
        deviceAuthorizationEndpointURI = URI.create("$protocolBaseUrl/auth/device")
        registrationEndpointURI = URI.create("$realmBaseUrl/clients-registrations/openid-connect")
        pushedAuthorizationRequestEndpointURI = URI.create("$protocolBaseUrl/ext/par/request")
        backChannelAuthenticationEndpointURI = URI.create("$protocolBaseUrl/ext/ciba/auth")
    }
    setSupportsAuthorizationResponseIssuerParam(true)
}
