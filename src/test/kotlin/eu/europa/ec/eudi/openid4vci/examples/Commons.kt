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
package eu.europa.ec.eudi.openid4vci.examples

import com.nimbusds.jose.jwk.Curve
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL

internal object PidDevIssuer {
    private const val BASE_URL = "https://dev.issuer-backend.eudiw.dev"
    private const val WALLET_CLIENT_ID = "wallet-dev"
    private val WalletRedirectURI = URI.create("urn:ietf:wg:oauth:2.0:oob")
    val IssuerId = CredentialIssuerId(BASE_URL).getOrThrow()
    val TestUser = ActingUser("tneal", "password")

    internal class ActingUser(
        val username: String,
        val password: String,
    )

    val PID_SdJwtVC_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_vc_sd_jwt")
    val PID_MsoMdoc_config_id = CredentialConfigurationIdentifier("eu.europa.ec.eudiw.pid_mso_mdoc")
    val MDL_config_id = CredentialConfigurationIdentifier("org.iso.18013.5.1.mDL")

    val AllCredentialConfigurationIds = listOf(
        PID_SdJwtVC_config_id,
        PID_MsoMdoc_config_id,
        MDL_config_id,
    )

    val Cfg = OpenId4VCIConfig(
        clientId = WALLET_CLIENT_ID,
        authFlowRedirectionURI = WalletRedirectURI,
        keyGenerationConfig = KeyGenerationConfig(Curve.P_256, 2048),
        credentialResponseEncryptionPolicy = CredentialResponseEncryptionPolicy.SUPPORTED,
        dPoPSigner = CryptoGenerator.ecProofSigner(),
    )

    suspend fun loginUserAndGetAuthCode(
        preparedAuthorizationCodeRequest: AuthorizationRequestPrepared,
        actingUser: ActingUser,
    ): Pair<String, String>? = coroutineScope {
        suspend fun extractASLoginUrl(html: String): URL = withContext(Dispatchers.IO) {
            val form = Jsoup.parse(html).body().getElementById("kc-form-login") as FormElement
            val action = form.attr("action")
            URL(action)
        }

        val response = createHttpClient().use { client ->
            val loginUrl = async {
                val url = preparedAuthorizationCodeRequest.authorizationCodeURL.value
                val loginHtml = client.get(url).body<String>()
                extractASLoginUrl(loginHtml)
            }
            client.submitForm(
                url = loginUrl.await().toString(),
                formParameters = Parameters.build {
                    append("username", actingUser.username)
                    append("password", actingUser.password)
                },
            )
        }
        val redirectLocation = response.headers["Location"].toString()
        with(URLBuilder(redirectLocation)) {
            parameters["code"] to parameters["state"]
        }.toNullable()
    }

    private fun <A, B> Pair<A?, B?>.toNullable(): Pair<A, B>? {
        return if (first != null && second != null) first!! to second!!
        else null
    }
}

val DefaultProofSignersMap = mapOf(
    PidDevIssuer.PID_SdJwtVC_config_id to CryptoGenerator.rsaProofSigner(),
    PidDevIssuer.PID_MsoMdoc_config_id to CryptoGenerator.ecProofSigner(),
    PidDevIssuer.MDL_config_id to CryptoGenerator.ecProofSigner(),
)

internal fun createHttpClient(enableLogging: Boolean = true): HttpClient = HttpClient(Apache) {
    install(ContentNegotiation) {
        json(
            json = Json { ignoreUnknownKeys = true },
        )
    }
    install(HttpCookies)
    if (enableLogging) {
        install(Logging) {
            logger = Logger.DEFAULT
            level = LogLevel.ALL
        }
    }
    engine {
        customizeClient {
            followRedirects = true
            setSSLContext(
                SSLContextBuilder.create().loadTrustMaterial(TrustSelfSignedStrategy()).build(),
            )
            setSSLHostnameVerifier(NoopHostnameVerifier())
        }
    }
}

internal fun authorizationLog(message: String) {
    println("--> [AUTHORIZATION] $message")
}

internal fun issuanceLog(message: String) {
    println("--> [ISSUANCE] $message")
}
