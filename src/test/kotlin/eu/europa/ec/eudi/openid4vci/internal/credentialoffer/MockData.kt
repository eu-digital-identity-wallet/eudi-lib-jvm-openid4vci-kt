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
package eu.europa.ec.eudi.openid4vci.internal.credentialoffer

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
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
import com.nimbusds.openid.connect.sdk.SubjectType
import com.nimbusds.openid.connect.sdk.claims.ACR
import com.nimbusds.openid.connect.sdk.claims.ClaimType
import com.nimbusds.openid.connect.sdk.op.OIDCProviderEndpointMetadata
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.formats.MsoMdoc
import eu.europa.ec.eudi.openid4vci.formats.W3CJsonLdDataIntegrity
import eu.europa.ec.eudi.openid4vci.formats.W3CJsonLdSignedJwt
import eu.europa.ec.eudi.openid4vci.formats.W3CSignedJwt
import io.ktor.http.*
import java.net.URI
import java.net.URL
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
        URLBuilder(credentialIssuerId.toString())
            .appendPathSegments("/.well-known/openid-credential-issuer", encodeSlash = false)
            .buildString(),
    ).getOrThrow()

/**
 * Gets the issuer of the Authorization Server used throughout the tests.
 */
internal fun authorizationServerIssuer() =
    HttpsUrl("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm").getOrThrow()

/**
 * Get the URL for fetching the metadata of the OpenID Connect Authorization Server used throughout the tests.
 */
internal fun oidcAuthorizationServerMetadataUrl(authorizationServerIssuer: HttpsUrl = authorizationServerIssuer()) =
    HttpsUrl(
        URLBuilder(authorizationServerIssuer.value.toString())
            .appendPathSegments("/.well-known/openid-configuration", encodeSlash = false)
            .buildString(),
    ).getOrThrow()

/**
 * Get the URL for fetching the metadata of the OAuth Authorization Server used throughout the tests.
 */
internal fun oauthAuthorizationServerMetadataUrl(authorizationServerIssuer: HttpsUrl = authorizationServerIssuer()) =
    HttpsUrl(
        URLBuilder(authorizationServerIssuer.value.toString())
            .appendPathSegments("/.well-known/oauth-authorization-server", encodeSlash = false)
            .buildString(),
    ).getOrThrow()

/**
 * Gets the 'UniversityDegree_JWT' scoped credential used throughout the tests.
 */
internal fun universityDegreeJwt() =
    W3CSignedJwt.Model.CredentialSupported(
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
        W3CSignedJwt.Model.CredentialSupported.CredentialDefinition(
            listOf("VerifiableCredential", "UniversityDegreeCredential"),
            mapOf(
                "given_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Given Name", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "family_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Surname", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "degree" to Claim(),
                "gpa" to Claim(
                    display = listOf(
                        Claim.Display(
                            "name", Locale.forLanguageTag("GPA"),
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
    W3CJsonLdDataIntegrity.Model.CredentialSupported(
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
        W3CJsonLdDataIntegrity.Model.CredentialSupported.CredentialDefinition(
            listOf(
                URL("https://www.w3.org/2018/credentials/v1"),
                URL("https://www.w3.org/2018/credentials/examples/v1"),
            ),
            listOf("VerifiableCredential_LDP_VC", "UniversityDegreeCredential_LDP_VC"),
            mapOf(
                "given_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Given Name", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "family_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Surname", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "degree" to Claim(),
                "gpa" to Claim(
                    display = listOf(
                        Claim.Display(
                            "name", Locale.forLanguageTag("GPA"),
                        ),
                    ),
                ),
            ),
        ),
        emptyList(),
    )

internal fun universityDegreeJwtVcJsonLD() =
    W3CJsonLdSignedJwt.Model.CredentialSupported(
        "UniversityDegree_JWT_VC_JSON-LD",
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
        W3CJsonLdSignedJwt.Model.CredentialSupported.CredentialDefinition(
            listOf(
                URL("https://www.w3.org/2018/credentials/v1"),
                URL("https://www.w3.org/2018/credentials/examples/v1"),
            ),
            listOf("VerifiableCredential_JWT_VC_JSON-LD", "UniversityDegreeCredential_JWT_VC_JSON-LD"),
            mapOf(
                "given_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Given Name", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "family_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Surname", Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "degree" to Claim(),
                "gpa" to Claim(
                    display = listOf(
                        Claim.Display(
                            "name", Locale.forLanguageTag("GPA"),
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
    MsoMdoc.Model.CredentialSupported(
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
                "given_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Given Name",
                            Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "family_name" to Claim(
                    display = listOf(
                        Claim.Display(
                            "Surname",
                            Locale.forLanguageTag("en-US"),
                        ),
                    ),
                ),
                "birth_date" to Claim(),
            ),
            "org.iso.18013.5.1.aamva" to mapOf(
                "organ_donor" to Claim(),
            ),
        ),
    )

/**
 * Gets the [CredentialIssuerMetadata] used throughout the tests.
 */
internal fun credentialIssuerMetadata() =
    CredentialIssuerMetadata(
        credentialIssuerId(),
        authorizationServerIssuer(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials").getOrThrow(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials/batch").getOrThrow(),
        CredentialIssuerEndpoint("https://credential-issuer.example.com/credentials/deferred").getOrThrow(),
        CredentialResponseEncryption.Required(
            listOf(
                JWEAlgorithm.ECDH_ES, JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.ECDH_ES_A256KW,
                JWEAlgorithm.RSA1_5, JWEAlgorithm.RSA_OAEP, JWEAlgorithm.RSA_OAEP_256, JWEAlgorithm.RSA_OAEP_384, JWEAlgorithm.RSA_OAEP_512,
            ),
            listOf(EncryptionMethod.XC20P),
        ),
        listOf(universityDegreeJwt(), mobileDrivingLicense(), universityDegreeLdpVc(), universityDegreeJwtVcJsonLD()),
        listOf(CredentialIssuerMetadata.Display("credential-issuer.example.com", "en-US")),
    )

/**
 * Gets the [OpenID Connect Authorization Server metadata][CIAuthorizationServerMetadata] used throughout the tests.
 */
internal fun oidcAuthorizationServerMetadata(): OIDCProviderMetadata =
    OIDCProviderMetadata(
        Issuer(authorizationServerIssuer().value),
        listOf(
            "public",
            "pairwise",
        ).map { SubjectType.parse(it) },
        URI.create("https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm/protocol/openid-connect/certs"),
    ).apply {
        val realmBaseUrl = "https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm"
        val oidcProtocolBaseUrl = "$realmBaseUrl/protocol/openid-connect"
        authorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth")
        tokenEndpointURI = URI.create("$oidcProtocolBaseUrl/token")
        introspectionEndpointURI = URI.create("$oidcProtocolBaseUrl/token/introspect")
        userInfoEndpointURI = URI.create("$oidcProtocolBaseUrl/userinfo")
        endSessionEndpointURI = URI.create("$oidcProtocolBaseUrl/logout")
        setSupportsFrontChannelLogoutSession(true)
        setSupportsFrontChannelLogout(true)
        checkSessionIframeURI = URI.create("$oidcProtocolBaseUrl/login-status-iframe.html")
        grantTypes = listOf(
            "authorization_code",
            "implicit",
            "refresh_token",
            "password",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:openid:params:grant-type:ciba",
        ).map { GrantType(it) }
        acRs = listOf(
            "0",
            "1",
        ).map { ACR(it) }
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
        idTokenJWSAlgs = listOf(
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
        idTokenJWEAlgs = listOf(
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
        ).map { JWEAlgorithm(it) }
        idTokenJWEEncs = listOf(
            "A256GCM",
            "A192GCM",
            "A128GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
        ).map { EncryptionMethod(it) }
        userInfoJWSAlgs = listOf(
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
        userInfoJWEAlgs = listOf(
            "RSA-OAEP",
            "RSA-OAEP-256",
            "RSA1_5",
        ).map { JWEAlgorithm(it) }
        userInfoJWEEncs = listOf(
            "A256GCM",
            "A192GCM",
            "A128GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
        ).map { EncryptionMethod(it) }
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
        claims = listOf(
            "aud",
            "sub",
            "iss",
            "auth_time",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "acr",
        )
        claimTypes = listOf(
            "normal",
        ).map { ClaimType.parse(it) }
        setSupportsClaimsParams(true)
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
        revocationEndpointURI = URI.create("$oidcProtocolBaseUrl/revoke")
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
        setSupportsBackChannelLogout(true)
        setSupportsBackChannelLogoutSession(true)
        deviceAuthorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth/device")
        backChannelTokenDeliveryModes = listOf(
            "poll",
            "ping",
        ).map { BackChannelTokenDeliveryMode(it) }
        backChannelAuthenticationEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/ciba/auth")
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
        pushedAuthorizationRequestEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/par/request")
        mtlsEndpointAliases = OIDCProviderEndpointMetadata().apply {
            tokenEndpointURI = URI.create("$oidcProtocolBaseUrl/token")
            revocationEndpointURI = URI.create("$oidcProtocolBaseUrl/revoke")
            introspectionEndpointURI = URI.create("$oidcProtocolBaseUrl/token/introspect")
            deviceAuthorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth/device")
            registrationEndpointURI = URI.create("$realmBaseUrl/clients-registrations/openid-connect")
            userInfoEndpointURI = URI.create("$oidcProtocolBaseUrl/userinfo")
            pushedAuthorizationRequestEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/par/request")
            backChannelAuthenticationEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/ciba/auth")
        }
        setSupportsAuthorizationResponseIssuerParam(true)
    }

/**
 * Gets the [OpenID Connect Authorization Server metadata][CIAuthorizationServerMetadata] used throughout the tests.
 */
internal fun oauthAuthorizationServerMetadata(): AuthorizationServerMetadata =
    AuthorizationServerMetadata(
        Issuer(authorizationServerIssuer().value),
    ).apply {
        val realmBaseUrl = "https://keycloak-eudi.netcompany-intrasoft.com/realms/pid-issuer-realm"
        val oidcProtocolBaseUrl = "$realmBaseUrl/protocol/openid-connect"
        authorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth")
        tokenEndpointURI = URI.create("$oidcProtocolBaseUrl/token")
        introspectionEndpointURI = URI.create("$oidcProtocolBaseUrl/token/introspect")
        jwkSetURI = URI.create("$oidcProtocolBaseUrl/certs")
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
        revocationEndpointURI = URI.create("$oidcProtocolBaseUrl/revoke")
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
        deviceAuthorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth/device")
        backChannelTokenDeliveryModes = listOf(
            "poll",
            "ping",
        ).map { BackChannelTokenDeliveryMode(it) }
        backChannelAuthenticationEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/ciba/auth")
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
        pushedAuthorizationRequestEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/par/request")
        mtlsEndpointAliases = AuthorizationServerEndpointMetadata().apply {
            tokenEndpointURI = URI.create("$oidcProtocolBaseUrl/token")
            revocationEndpointURI = URI.create("$oidcProtocolBaseUrl/revoke")
            introspectionEndpointURI = URI.create("$oidcProtocolBaseUrl/token/introspect")
            deviceAuthorizationEndpointURI = URI.create("$oidcProtocolBaseUrl/auth/device")
            registrationEndpointURI = URI.create("$realmBaseUrl/clients-registrations/openid-connect")
            pushedAuthorizationRequestEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/par/request")
            backChannelAuthenticationEndpointURI = URI.create("$oidcProtocolBaseUrl/ext/ciba/auth")
        }
        setSupportsAuthorizationResponseIssuerParam(true)
    }
