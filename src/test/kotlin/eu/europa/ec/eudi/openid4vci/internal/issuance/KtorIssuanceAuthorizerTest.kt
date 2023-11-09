package eu.europa.ec.eudi.openid4vci.internal.issuance

import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.util.*
import kotlin.test.*


class KtorIssuanceAuthorizerTest {

    val CredentialIssuer_URL = "https://credential-issuer.example.com"

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "MyWallet_ClientId",
        authFlowRedirectionURI = URI.create("eudi-wallet//auth"),
    )

    @Test
    fun `successful authorization with authorization code flow (wallet initiated)`() {
        runBlocking {

            val credentialIssuerIdentifier = CredentialIssuerId(CredentialIssuer_URL).getOrThrow()
            val ktorHttpClientFactory = mockedKtorHttpClientFactory(
                listOf(
                    authServerWellKnownMocker(),
                    openIdWellKnownMocker(),
                    parPostMocker { request ->
                        assertTrue("Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}") {
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
                        assertTrue("Wrong content-type, expected application/x-www-form-urlencoded but was ${request.headers["Content-Type"]}") {
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
                        assertTrue("Expected grant_type is ${TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE} but instead sent $grantType.") {
                            grantType == TokenEndpointForm.AuthCodeFlow.GRANT_TYPE_PARAM_VALUE
                        }
                    }
                )
            )

            val issuerMetadata =
                CredentialIssuerMetadataResolver.ktor(
                    ktorHttpClientFactory = ktorHttpClientFactory
                )
                    .resolve(credentialIssuerIdentifier).getOrThrow()

            val authServerMetadata =
                AuthorizationServerMetadataResolver.ktor(
                    ktorHttpClientFactory = ktorHttpClientFactory
                )
                    .resolve(issuerMetadata.authorizationServer).getOrThrow()

            val issuer = Issuer.make(
                IssuanceAuthorizer.ktor(
                    authorizationServerMetadata= authServerMetadata,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                    config = vciWalletConfiguration,
                ),
                IssuanceRequester.ktor(
                    issuerMetadata = issuerMetadata,
                    ktorHttpClientFactory = ktorHttpClientFactory,
                ),
            )
            with(issuer) {
                val parRequested =
                    pushAuthorizationCodeRequest(
                        listOf(
                            CredentialMetadata.ByScope(Scope.of("eu.europa.ec.eudiw.pid_mso_mdoc")),
                            CredentialMetadata.ByScope(Scope.of("eu.europa.ec.eudiw.pid_vc_sd_jwt"))
                        ), null).getOrThrow()

                val authorizationCode = UUID.randomUUID().toString()

                parRequested
                    .handleAuthorizationCode(IssuanceAuthorization.AuthorizationCode(authorizationCode)).also { println(it) }
                    .requestAccessToken().getOrThrow().also { println(it) }
            }

        }

    }

    private fun openIdWellKnownMocker():  RequestMockerValidator = RequestMockerValidator(
        requestMatcher = endsWithMatch("/.well-known/openid-credential-issuer", HttpMethod.Get),
        responseBuilder = {
            respond(
                content = getResourceAsText("well-known/openid-credential-issuer_no_encryption.json"),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        validator = {},
    )

    private fun authServerWellKnownMocker():  RequestMockerValidator = RequestMockerValidator(
        requestMatcher = endsWithMatch("/.well-known/openid-configuration", HttpMethod.Get),
        responseBuilder = {
            respond(
                content = getResourceAsText("well-known/openid-configuration.json"),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        validator = {},
    )

    private fun parPostMocker(validator: (request: HttpRequestData) -> Unit):  RequestMockerValidator = RequestMockerValidator(
        requestMatcher = endsWithMatch("/ext/par/request", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    PushedAuthorizationRequestResponse.Success(
                        "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                        3600,
                    )
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        validator = validator,
    )

    private fun tokenPostMocker(validator: (request: HttpRequestData) -> Unit):  RequestMockerValidator = RequestMockerValidator(
        requestMatcher = endsWithMatch("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    AccessTokenRequestResponse.Success(
                        accessToken = UUID.randomUUID().toString(),
                        expiresIn = 3600,
                    )
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        validator = validator,
    )

    private fun mockedKtorHttpClientFactory(requestMockers: List<RequestMockerValidator>): KtorHttpClientFactory = {
        HttpClient(MockEngine) {
            install(ContentNegotiation) {
                json(
                    json = Json { ignoreUnknownKeys = true },
                )
            }
            engine {
                addHandler {request ->
                    requestMockers
                        .firstOrNull {it.requestMatcher(request)}
                        ?.apply {
                            validator(request)
                        }
                        ?.responseBuilder?.invoke(this)
                        ?: respondError(HttpStatusCode.NotFound)

                }
            }
        }
    }
}
internal data class RequestMockerValidator(
    val requestMatcher: HttpRequestDataMatcher,
    val responseBuilder: HttpResponseDataBuilder,
    val validator: (request: HttpRequestData) -> Unit,
)

