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

import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
import eu.europa.ec.eudi.openid4vci.internal.issuance.KtorIssuanceAuthorizer
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL

val MsoMdoc_CredentialOffer = """
    {
      "credential_issuer": "http://localhost:8080",
      "credentials": [
        "eu.europa.ec.eudiw.pid_mso_mdoc"
      ],
      "grants": {
        "authorization_code": {
          "issuer_state": "eyJhbGciOiJSU0EtFYUaBy"
        }
      }
    }
""".trimIndent()

fun main(): Unit = runBlocking {
    val actingUser = ActingUser("babis", "babis")
    val wallet = Wallet.ofUser(actingUser)

    val coUrl = "http://localhost:8080/credentialoffer?credential_offer=$MsoMdoc_CredentialOffer"
    wallet.authorizeIssuance(coUrl)
}

data class ActingUser(
    val username: String,
    val password: String,
)

private class Wallet(
    val actingUser: ActingUser,
) {

    val vciWalletConfiguration = WalletOpenId4VCIConfig(
        clientId = "wallet-dev",
        clientSecret = "dvGPqa3Spk3KU2nljDIzCixbm9y3HXWN",
        authFlowRedirectionURI = URI.create("urn:ietf:wg:oauth:2.0:oob"),
    )

    suspend fun authorizeIssuance(coUrl: String): IssuanceAccessToken {
        val ktorHttpClient = defaultHttpClientFactory()
        val credentialOfferRequestResolver = CredentialOfferRequestResolver(
            httpGet = { url ->
                runCatching {
                    ktorHttpClient.get(url).body<String>()
                }
            },
        )

        val offer = credentialOfferRequestResolver.resolve(coUrl).getOrThrow()

        val asMetadata = resolveASMetadata(offer.credentialIssuerMetadata.authorizationServer.value.toURL())
        val issuer = AuthorizationCodeFlowIssuer.ktor(asMetadata, vciWalletConfiguration)

        return with(issuer) {
            println("--> Placing PAR to AS server's endpoint ${asMetadata.pushedAuthorizationRequestEndpointURI}")

            val parPlaced = placePushedAuthorizationRequest(offer.credentials, null).getOrThrow()

            println("--> Placed PAR. Get authorization code URL is: ${parPlaced.getAuthorizationCodeURL.url.value}")

            val authorizationCode = loginUserAndGetAuthCode(
                parPlaced.getAuthorizationCodeURL.url.value.toURL(),
                actingUser,
            ) ?: error("Could not retrieve authorization code")

            println("--> Authorization code retrieved: $authorizationCode")

            parPlaced
                .authorize(authorizationCode).getOrThrow()
                .placeAccessTokenRequest().getOrThrow()
                .token.also {
                    println("--> Authorization code exchanged with access token : ${it.accessToken}")
                }
        }
    }

    private fun httpClientWithHttpCookiesFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) { json() }
            install(HttpCookies)
//            expectSuccess = true
        }

    private fun defaultHttpClientFactory(): HttpClient =
        HttpClient {
            install(ContentNegotiation) {
                json(
                    json = Json { ignoreUnknownKeys = true },
                )
            }
            expectSuccess = true
        }

    private suspend fun resolveASMetadata(
        authorizationServerUrl: URL,
    ): AuthorizationServerMetadata {
        val client = KtorIssuanceAuthorizer.DefaultFactory()
        val getASMetadata = object : HttpGet<String> {
            override suspend fun get(url: URL): Result<String> = runCatching {
                client.get(url).body<String>()
            }
        }

        val asMetadataURL = authorizationServerUrl.toString().let {
            if (it.endsWith("/")) {
                URL(authorizationServerUrl.toString() + ".well-known/openid-configuration")
            } else {
                URL(authorizationServerUrl.toString() + "/.well-known/openid-configuration")
            }
        }

        val metadata = getASMetadata.get(asMetadataURL).getOrThrow()
        return AuthorizationServerMetadata.parse(metadata)
    }

    private suspend fun loginUserAndGetAuthCode(getAuthorizationCodeUrl: URL, actingUser: ActingUser): String? {
        val client = httpClientWithHttpCookiesFactory()

        val loginUrl = HttpGet { url ->
            runCatching {
                client.get(url).body<String>()
            }
        }.get(getAuthorizationCodeUrl).getOrThrow().extractASLoginUrl()

        return HttpFormPost { url, formParameters ->
            val response = client.submitForm(
                url = url.toString(),
                formParameters = Parameters.build {
                    formParameters.entries.forEach { append(it.key, it.value) }
                },
            )
            val redirectLocation = response.headers.get("Location").toString()
            URLBuilder(redirectLocation).parameters.get("code")
        }.post(
            loginUrl,
            mapOf(
                "username" to actingUser.username,
                "password" to actingUser.password,
            ),
        )
    }

    private fun String.extractASLoginUrl(): URL {
        val form = Jsoup.parse(this).body().getElementById("kc-form-login") as FormElement
        val action = form.attr("action")
        return URL(action)
    }

    companion object {
        fun ofUser(actingUser: ActingUser) = Wallet(actingUser)
    }
}
