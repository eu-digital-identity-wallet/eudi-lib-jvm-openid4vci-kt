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
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.test.runTest
import parPostApplyAssertionsAndGetFormData
import tokenPostApplyAuthFlowAssertionsAndGetFormData
import java.net.URI
import java.util.*
import kotlin.test.*

class AuthorizationResponseIssCheckerTest {

    private val validIss = "https://auth-server.example.com"
    private val invalidIss = "https://evil.example.com/realms/pid-issuer-realm"

    private fun config(authResponseIssChecking: AuthorizationResponseIssChecking): OpenId4VCIConfig =
        OpenId4VCIConfig(
            clientAuthentication = ClientAuthentication.None("MyWallet_ClientId"),
            authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
            encryptionSupportConfig = EncryptionSupportConfig(
                Curve.P_256,
                2048,
                CredentialResponseEncryptionPolicy.SUPPORTED,
            ),
            proofs = ProofsConfig.Default,
            authResponseIssChecking = authResponseIssChecking,
        )

    private suspend fun issuerWith(
        config: OpenId4VCIConfig,
        mockedHttpClient: HttpClient,
        credentialOfferStr: String = CredentialOfferMixedDocTypes_NO_GRANTS,
    ): Issuer = Issuer.make(
        config = config,
        credentialOfferUri = "openid-credential-offer://?credential_offer=$credentialOfferStr",
        httpClient = mockedHttpClient,
    ).getIssuerOrThrow()

    @Test
    fun `IfSupported - valid iss succeeds`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.IfSupported), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state, issuer = validIss)
                .getOrThrow()
        }
    }

    @Test
    fun `IfSupported - mismatched iss fails`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.IfSupported), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state, issuer = invalidIss)
                .fold(
                    onSuccess = { fail("Expected failure due to mismatched iss") },
                    onFailure = {
                        assertTrue(
                            it is CredentialIssuanceError.InvalidAuthorizationIssuer,
                            "Expected InvalidAuthorizationIssuer but was $it",
                        )
                    },
                )
        }
    }

    @Test
    fun `IfSupported - missing iss when supported fails`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.IfSupported), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state)
                .fold(
                    onSuccess = { fail("Expected failure due to missing iss") },
                    onFailure = {
                        assertTrue(
                            it is CredentialIssuanceError.MissingAuthorizationResponseIssuer,
                            "Expected MissingAuthorizationResponseIssuer but was $it",
                        )
                    },
                )
        }
    }

    @Test
    fun `Never - missing iss succeeds (no check)`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.Never), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state)
                .getOrThrow()
        }
    }

    @Test
    fun `Required - valid iss succeeds`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.Required), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state, issuer = validIss)
                .getOrThrow()
        }
    }

    @Test
    fun `Required - missing iss fails`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMocker(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.Required), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state)
                .fold(
                    onSuccess = { fail("Expected failure due to missing iss") },
                    onFailure = {
                        assertTrue(
                            it is CredentialIssuanceError.MissingAuthorizationResponseIssuer,
                            "Expected MissingAuthorizationResponseIssuer but was $it",
                        )
                    },
                )
        }
    }

    @Test
    fun `Required - AS does not support iss param fails`() = runTest {
        val mockedHttpClient = mockedHttpClient(
            credentialIssuerMetadataWellKnownMocker(),
            authServerWellKnownMockerWithoutIssParam(),
            parPostMocker { with(it) { parPostApplyAssertionsAndGetFormData(false) } },
            tokenPostMocker { request -> with(request) { tokenPostApplyAuthFlowAssertionsAndGetFormData() } },
        )
        val issuer = issuerWith(config(AuthorizationResponseIssChecking.Required), mockedHttpClient)
        with(issuer) {
            val authRequestPrepared = prepareAuthorizationRequest().getOrThrow()
            val code = UUID.randomUUID().toString()
            authRequestPrepared
                .authorizeWithAuthorizationCode(AuthorizationCode(code), authRequestPrepared.state, issuer = validIss)
                .fold(
                    onSuccess = { fail("Expected failure because AS does not support iss param") },
                    onFailure = {
                        assertTrue(
                            it is CredentialIssuanceError.AuthorizationResponseIssuerParamNotSupported,
                            "Expected AuthorizationResponseIssuerParamNotSupported but was $it",
                        )
                    },
                )
        }
    }

    private fun authServerWellKnownMockerWithoutIssParam(): RequestMocker =
        RequestMocker(
            requestMatcher = { request ->
                request.url.encodedPath.contains("/.well-known/oauth-authorization-server") && request.method == HttpMethod.Get
            },
            responseBuilder = {
                val content = getResourceAsText("well-known/openid-configuration.json")
                    .replace(Regex("\"authorization_response_iss_parameter_supported\"\\s*:\\s*true\\s*,?\\s*"), "")
                respond(
                    content = content,
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType to listOf("application/json")),
                )
            },
        )
}
