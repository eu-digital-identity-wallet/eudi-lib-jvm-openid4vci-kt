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

import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.addAll
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URI
import java.net.URL
import java.net.URLEncoder

interface CanBeUsedWithVciLib {
    val cfg: OpenId4VCIConfig

    suspend fun createIssuer(credentialOfferUri: String, enableHttLogging: Boolean = false): Issuer {
        return Issuer.make(cfg, credentialOfferUri, { createHttpClient(enableHttLogging) }).getOrThrow()
    }
}

data class CredentialOfferForm<USER>(
    val user: USER,
    val credentialConfigurationIds: Set<CredentialConfigurationIdentifier>,
    val authorizationCodeGrant: AuthorizationCodeGrant?,
    val preAuthorizedCodeGrant: PreAuthorizedCodeGrant?,
    val credentialOfferEndpoint: String?,
) {
    companion object {
        fun <USER> authorizationCodeGrant(
            user: USER,
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
            user: USER,
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

interface CanRequestForCredentialOffer<USER> {
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

/**
 * An authorization server, with a known user
 * that can issue credentials
 */
interface HasTestUser<USER> {
    val testUser: USER
}

/**
 * The ability of an authorization server, to allow a [USER]
 * to authorize credential issuance
 */
interface CanAuthorizeIssuance<USER> {

    suspend fun loginUserAndGetAuthCode(
        authorizationRequestPrepared: AuthorizationRequestPrepared,
        user: USER,
        enableHttpLogging: Boolean = false,
    ): Pair<String, String> = coroutineScope {
        suspend fun HttpClient.visitAuthorizationPage(): HttpResponse {
            val url = authorizationRequestPrepared.authorizationCodeURL.toString()
            return get(url)
        }

        val response = createHttpClient(enableLogging = enableHttpLogging).use { httpClient ->

            val loginPageResponse = httpClient.visitAuthorizationPage()
            check(loginPageResponse.status.isSuccess()) { "Response for login page was ${loginPageResponse.status}" }
            val loginHtml = loginPageResponse.body<String>()
            httpClient.authorizeIssuance(loginHtml, user)
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

    suspend fun HttpClient.authorizeIssuance(loginHtml: String, user: USER): HttpResponse
}

//
// Keycloak Support
//
data class KeycloakUser(val username: String, val password: String)

object Keycloak : CanAuthorizeIssuance<KeycloakUser> {
    override suspend fun HttpClient.authorizeIssuance(loginHtml: String, user: KeycloakUser): HttpResponse {
        suspend fun extractASLoginUrl(): URL = withContext(Dispatchers.IO) {
            val form = Jsoup.parse(loginHtml).body().getElementById("kc-form-login") as FormElement
            val action = form.attr("action")
            URL(action)
        }

        fun formParameters() = Parameters.build {
            append("username", user.username)
            append("password", user.password)
        }
        return coroutineScope {
            val loginUrl = extractASLoginUrl()
            submitForm(url = loginUrl.toString(), formParameters = formParameters())
        }
    }
}
