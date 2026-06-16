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
package eu.europa.ec.eudi.openid4vci.examples

import com.eygraber.uri.Uri
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.JsonSupport
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.openqa.selenium.By
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import java.net.URI
import java.net.URLEncoder
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

interface HasIssuerId {
    val issuerId: CredentialIssuerId
}

interface CanBeUsedWithVciLib {
    val cfg: OpenId4VCIConfig

    suspend fun createIssuer(credentialOfferUri: String, httpClient: HttpClient): Issuer {
        return Issuer.make(cfg, credentialOfferUri, httpClient).getOrThrow()
    }
}

data class CredentialOfferForm<out USER>(
    val user: USER?,
    val credentialConfigurationIds: Set<CredentialConfigurationIdentifier>,
    val authorizationCodeGrant: AuthorizationCodeGrant?,
    val preAuthorizedCodeGrant: PreAuthorizedCodeGrant?,
    val credentialOfferEndpoint: String?,
) {
    companion object {
        fun <USER> authorizationCodeGrant(
            user: USER?,
            credentialConfigurationIds: Set<CredentialConfigurationIdentifier>,
            issuerStateIncluded: Boolean = true,
            credentialOfferEndpoint: String? = null,
        ): CredentialOfferForm<USER> = CredentialOfferForm(
            user,
            credentialConfigurationIds,
            AuthorizationCodeGrant(issuerStateIncluded),
            null,
            credentialOfferEndpoint,
        )

        fun <USER> preAuthorizedCodeGrant(
            user: USER?,
            credentialConfigurationIds: Set<CredentialConfigurationIdentifier>,
            txCode: String?,
            credentialOfferEndpoint: String? = null,
        ): CredentialOfferForm<USER> = CredentialOfferForm(
            user,
            credentialConfigurationIds,
            null,
            PreAuthorizedCodeGrant(txCode, "text", null),
            credentialOfferEndpoint,
        )
    }

    data class AuthorizationCodeGrant(
        val issuerStateIncluded: Boolean = false,
    )

    data class PreAuthorizedCodeGrant(
        val txCode: String?,
        val txCodeInputMode: String = "numeric", // or text
        val txCodeDescription: String?,
    )
}

interface CanRequestForCredentialOffer<in USER> {
    suspend fun requestCredentialOffer(form: CredentialOfferForm<USER>): URI =
        createHttpClient(enableLogging = false).use { requestCredentialOffer(it, form) }

    suspend fun requestCredentialOffer(httpClient: HttpClient, form: CredentialOfferForm<USER>): URI

    companion object {
        @OptIn(ExperimentalSerializationApi::class)
        fun <USER> onlyStatelessAuthorizationCode(
            credentialIssuerId: CredentialIssuerId,
        ): CanRequestForCredentialOffer<USER> = object : CanRequestForCredentialOffer<USER> {
            override suspend fun requestCredentialOffer(
                httpClient: HttpClient,
                form: CredentialOfferForm<USER>,
            ): URI {
                val offerJson = buildJsonObject {
                    put("credential_issuer", credentialIssuerId.toString())
                    putJsonArray("credential_configuration_ids") {
                        addAll(form.credentialConfigurationIds.map { it.value })
                    }
                }.let { URLEncoder.encode(it.toString(), "UTF-8") }

                val endPoint = form.credentialOfferEndpoint ?: "openid-credential-offer://"

                return URI.create("$endPoint?credential_offer=$offerJson")
            }
        }
    }
}

fun interface CanRequestKeyAttestation {
    suspend fun requestKeyAttestation(
        attestedKeys: List<JWK>,
        nonce: Nonce?,
        preferredKeyStorageStatusPeriod: PositiveDuration?,
    ): KeyAttestationJWT

    companion object {
        fun usingCryptoGenerator(): CanRequestKeyAttestation =
            CanRequestKeyAttestation { attestedKeys, nonce, preferredKeyStorageStatusPeriod ->
                CryptoGenerator.keyAttestationJwt(attestedKeys, nonce, preferredKeyStorageStatusPeriod)
            }

        fun usingWalletProviderService(
            url: Url,
            enableLogging: Boolean = false,
        ): CanRequestKeyAttestation = RequestKeyAttestationFromWalletProviderService(url, enableLogging)
    }

    private class RequestKeyAttestationFromWalletProviderService(
        private val url: Url,
        enableLogging: Boolean = false,
    ) : CanRequestKeyAttestation {
        private val httpClient by lazy { createHttpClient(enableLogging) }

        override suspend fun requestKeyAttestation(
            attestedKeys: List<JWK>,
            nonce: Nonce?,
            preferredKeyStorageStatusPeriod: PositiveDuration?,
        ): KeyAttestationJWT {
            val request = Request(attestedKeys, nonce, preferredKeyStorageStatusPeriod)
            val response = httpClient.post(url) {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(request)
            }.body<Response>()
            return KeyAttestationJWT(response.keyAttestation)
        }

        @Serializable
        private data class Request(
            @SerialName("nonce") val nonce: String? = null,
            @SerialName("jwkSet") @Required val jwkSet: JsonObject,
            @SerialName("preferredKeyStorageStatusPeriod") val preferredKeyStorageStatusPeriod: DurationAsSeconds? = null,
        ) {
            companion object {
                operator fun invoke(keys: List<JWK>, nonce: Nonce?, preferredKeyStorageStatusPeriod: PositiveDuration?): Request {
                    val jwkSet = JsonSupport.decodeFromString<JsonObject>(
                        JSONObjectUtils.toJSONString(JWKSet(keys).toJSONObject(true)),
                    )
                    return Request(nonce?.value, jwkSet, preferredKeyStorageStatusPeriod?.value)
                }
            }
        }

        @Serializable
        private data class Response(
            @SerialName("keyAttestation") @Required val keyAttestation: String,
        )
    }
}

/**
 * An authorization server, with a known user
 * that can issue credentials
 */
data object NoUser
interface HasTestUser<out USER> {
    val testUser: USER

    companion object {
        @Suppress("unused")
        val HasNoTestUser: HasTestUser<NoUser> = object : HasTestUser<NoUser> {
            override val testUser: NoUser = NoUser
        }
    }
}

/**
 * The ability of an authorization server, to allow a [USER]
 * to authorize credential issuance
 */
interface CanAuthorizeIssuance<in USER> {

    suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: USER,
        httpClient: HttpClient,
    ): Pair<String, String> = coroutineScope {
        val response = run {
            val loginPageResponse = httpClient.visitAuthorizationPage(authorizationRequestPrepared)
            httpClient.authorizeIssuance(loginPageResponse, user)
        }
        response.parseCodeAndStatus()
    }

    fun HttpResponse.parseCodeAndStatus(): Pair<String, String> {
        fun <A, B> Pair<A?, B?>.toNullable(): Pair<A, B>? {
            return if (first != null && second != null) first!! to second!!
            else null
        }

        val redirectLocation = headers["Location"].toString()
        return with(URLBuilder(redirectLocation)) {
            parameters["code"] to parameters["state"]
        }.toNullable() ?: error("Failed to get authorization code & state")
    }

    suspend fun HttpClient.visitAuthorizationPage(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
    ): HttpResponse {
        val url = authorizationRequestPrepared.authorizationCodeURL.toString()
        return get(url) {
            headers {
                append(HttpHeaders.Accept, "text/html")
            }
        }
    }

    suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: USER): HttpResponse
}

//
// Keycloak Support
//
data class KeycloakUser(val username: String, val password: String)

object Keycloak : CanAuthorizeIssuance<KeycloakUser> {
    override suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: KeycloakUser,
        httpClient: HttpClient,
    ): Pair<String, String> {
        val driver = ChromeDriver(ChromeOptions().apply { addArguments("--ignore-certificate-errors") })
            .apply {
                with(manage().timeouts()) {
                    implicitlyWait(10.seconds.toJavaDuration())
                    scriptTimeout(10.seconds.toJavaDuration())
                    pageLoadTimeout(10.seconds.toJavaDuration())
                }
            }

        val redirectUri = withContext(Dispatchers.IO) {
            try {
                driver.get(authorizationRequestPrepared.authorizationCodeURL.toString())

                driver.findElement(By.id("username")).sendKeys(user.username)
                driver.findElement(By.id("password")).sendKeys(user.password)
                driver.findElement(By.id("kc-login")).click()

                Uri.parse(driver.currentUrl)
            } finally {
                driver.quit()
            }
        }

        val authorizationCode = redirectUri.getQueryParameter("code") ?: error("Authorization code not found in redirect URI")
        val state = redirectUri.getQueryParameter("state") ?: error("State not found in redirect URI")

        return authorizationCode to state
    }

    override suspend fun HttpClient.authorizeIssuance(loginResponse: HttpResponse, user: KeycloakUser): HttpResponse = loginResponse

    val DebugRedirectUri: URI = URI.create("https://oauthdebugger.com/debug")
}
