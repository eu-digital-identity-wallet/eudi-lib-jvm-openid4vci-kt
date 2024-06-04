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

import eu.europa.ec.eudi.openid4vci.AuthorizationRequestPrepared
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.jsoup.Jsoup
import org.jsoup.nodes.FormElement
import java.net.URL

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

            val loginHtml = httpClient.visitAuthorizationPage().body<String>()
            httpClient.authorizeIssuance(loginHtml, user)
        }
        response.pareseCodeAndStatus()
    }

    fun HttpResponse.pareseCodeAndStatus(): Pair<String, String> {
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
