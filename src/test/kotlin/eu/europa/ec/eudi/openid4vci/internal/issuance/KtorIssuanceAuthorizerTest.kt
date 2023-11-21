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
package eu.europa.ec.eudi.openid4vci.internal.issuance

import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.formats.CredentialMetadata
import io.ktor.client.request.forms.*
import kotlinx.coroutines.test.runTest
import java.net.URI
import java.net.URLEncoder
import java.util.*
import kotlin.test.*

class KtorIssuanceAuthorizerTest {

    val CredentialIssuer_URL = "https://credential-issuer.example.com"

    val vciWalletConfiguration = OpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `successful authorization with authorization code flow`() {
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    oidcWellKnownMocker(),
                    authServerWellKnownMocker(),
                    parPostMocker { request ->
                        assertTrue(
                            "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                        ) {
                            request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                        }
                        assertTrue("Not a form post") {
                            request.body is FormDataContent
                        }

                        val form = request.body as FormDataContent

                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_vc_sd_jwt") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_vc_sd_jwt") ?: false
                        }
                        assertTrue("Missing scope eu.europa.ec.eudiw.pid_mso_mdoc") {
                            form.formData["scope"]?.contains("eu.europa.ec.eudiw.pid_mso_mdoc") ?: false
                        }
                        assertTrue("No issuer_state expected when issuance starts from wallet") {
                            form.formData["issuer_state"] == null
                        }
                        assertTrue("PKCE code challenge was expected but not sent.") {
                            form.formData["code_challenge"] != null
                        }
                        assertTrue("PKCE code challenge method was expected but not sent.") {
                            form.formData["code_challenge_method"] != null
                        }
                    },
                    tokenPostMocker { request ->
                        assertTrue(
                            "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                        ) {
                            request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                        }
                        assertTrue("Not a form post") {
                            request.body is FormDataContent
                        }
                        val form = request.body as FormDataContent
                        assertTrue("PKCE code verifier was expected but not sent.") {
                            form.formData[TokenEndpointForm.AuthCodeFlow.CODE_VERIFIER_PARAM] != null
                        }
                        assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM} was expected but not sent.") {
                            form.formData[TokenEndpointForm.AuthCodeFlow.AUTHORIZATION_CODE_PARAM] != null
                        }
                        assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM} was expected but not sent.") {
                            form.formData[TokenEndpointForm.AuthCodeFlow.REDIRECT_URI_PARAM] != null
                        }
                        assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM} was expected but not sent.") {
                            form.formData[TokenEndpointForm.AuthCodeFlow.CLIENT_ID_PARAM] != null
                        }
                        val grantType = form.formData[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                        assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.") {
                            grantType != null
                        }
                        assertTrue(
                            "Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.",
                        ) {
                            grantType == TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE
                        }
                    },
                ),
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            with(issuer) {
                val parRequested =
                    pushAuthorizationCodeRequest(
                        listOf(
                            CredentialMetadata.ByScope(Scope("eu.europa.ec.eudiw.pid_mso_mdoc")),
                            CredentialMetadata.ByScope(Scope("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
                        ),
                        null,
                    ).getOrThrow()

                val authorizationCode = UUID.randomUUID().toString()

                parRequested
                    .handleAuthorizationCode(AuthorizationCode(authorizationCode))
                    .also { println(it) }
                    .requestAccessToken().getOrThrow().also { println(it) }
            }
        }
    }

    @Test
    fun `successful authorization with pre-authorization code flow`() {
        runTest {
            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    authServerWellKnownMocker(),
                    oidcWellKnownMocker(),
                    parPostMocker {
                        fail("No pushed authorization request should have been sent in case of pre-authorized code flow")
                    },
                    tokenPostMocker { request ->
                        assertTrue(
                            "Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}",
                        ) {
                            request.body.contentType?.toString() == "application/x-www-form-urlencoded; charset=UTF-8"
                        }
                        assertTrue("Not a form post") {
                            request.body is FormDataContent
                        }
                        val form = request.body as FormDataContent

                        assertTrue("PKCE code verifier was not expected but sent.") {
                            form.formData["code_verifier"] != null
                        }
                        assertTrue("Parameter ${TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM} was expected but not sent.") {
                            form.formData[TokenEndpointForm.PreAuthCodeFlow.PRE_AUTHORIZED_CODE_PARAM] != null
                        }
                        assertTrue("Parameter ${TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM} was expected but not sent.") {
                            form.formData[TokenEndpointForm.PreAuthCodeFlow.USER_PIN_PARAM] != null
                        }

                        val grantType = form.formData[TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM]
                        assertTrue("Parameter ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM} was expected but not sent.") {
                            grantType != null
                        }

                        val grantTypeParamValueUrlEncoded =
                            URLEncoder.encode(TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE, "UTF-8")
                        assertTrue(
                            "Expected grant_type is ${TokenEndpointForm.PreAuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but got $grantType.",
                        ) {
                            grantTypeParamValueUrlEncoded == grantType
                        }
                    },
                ),
            )

            val issuer = issuer(mockedKtorHttpClientFactory, credentialIssuerIdentifier)
            with(issuer) {
                authorizeWithPreAuthorizationCode(
                    listOf(
                        CredentialMetadata.ByScope(Scope("eu.europa.ec.eudiw.pid_mso_mdoc")),
                        CredentialMetadata.ByScope(Scope("eu.europa.ec.eudiw.pid_vc_sd_jwt")),
                    ),
                    PreAuthorizationCode("eyJhbGciOiJSU0EtFYUaBy", "pin"),
                )
            }
        }
    }

    private suspend fun issuer(
        ktorHttpClientFactory: KtorHttpClientFactory,
        credentialIssuerIdentifier: CredentialIssuerId,
    ): Issuer {
        val issuerMetadata =
            CredentialIssuerMetadataResolver.ktor(
                ktorHttpClientFactory = ktorHttpClientFactory,
            ).resolve(credentialIssuerIdentifier).getOrThrow()

        val authServerMetadata =
            AuthorizationServerMetadataResolver.ktor(
                ktorHttpClientFactory = ktorHttpClientFactory,
            ).resolve(issuerMetadata.authorizationServer).getOrThrow()

        val issuer = Issuer.make(
            IssuanceAuthorizer.ktor(
                authorizationServerMetadata = authServerMetadata,
                ktorHttpClientFactory = ktorHttpClientFactory,
                config = vciWalletConfiguration,
            ),
            IssuanceRequester.ktor(
                issuerMetadata = issuerMetadata,
                ktorHttpClientFactory = ktorHttpClientFactory,
            ),
        )
        return issuer
    }
}
