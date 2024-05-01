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

import eu.europa.ec.eudi.openid4vci.EncryptedResponses.*
import eu.europa.ec.eudi.openid4vci.internal.http.PushedAuthorizationRequestResponseTO
import eu.europa.ec.eudi.openid4vci.internal.http.TokenResponseTO
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.util.*

internal fun credentialIssuerMetaDataHandler(id: CredentialIssuerId, resource: String): RequestMocker = RequestMocker(
    match(id.metaDataUrl().value.toURI()),
    jsonResponse(resource),
)

internal fun oidcMetaDataHandler(oidcServerUrl: HttpsUrl, oidcMetaDataResource: String): RequestMocker = RequestMocker(
    match(oidcAuthorizationServerMetadataUrl(oidcServerUrl).value.toURI()),
    jsonResponse(oidcMetaDataResource),
)

internal fun oauthMetaDataHandler(oauth2ServerUrl: HttpsUrl, oauth2MetaDataResource: String): RequestMocker = RequestMocker(
    match(oauthAuthorizationServerMetadataUrl(oauth2ServerUrl).value.toURI()),
    jsonResponse(oauth2MetaDataResource),
)

internal fun oidcWellKnownMocker(encryptedResponses: EncryptedResponses = NOT_SUPPORTED): RequestMocker = RequestMocker(
    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
    responseBuilder = {
        val content = when (encryptedResponses) {
            REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json")
            NOT_SUPPORTED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_supported.json")
            SUPPORTED_NOT_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_required.json")
        }
        respond(
            content = content,
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    },
)

enum class EncryptedResponses {
    REQUIRED, NOT_SUPPORTED, SUPPORTED_NOT_REQUIRED
}

internal fun authServerWellKnownMocker(): RequestMocker = RequestMocker(
    requestMatcher = endsWith("/.well-known/openid-configuration", HttpMethod.Get),
    responseBuilder = {
        respond(
            content = getResourceAsText("well-known/openid-configuration.json"),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    },
)

internal fun parPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/ext/par/request", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    PushedAuthorizationRequestResponseTO.Success(
                        "org:example:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c",
                        3600,
                    ),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun tokenPostMocker(validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    TokenResponseTO.Success(
                        accessToken = UUID.randomUUID().toString(),
                        expiresIn = 3600,
                    ),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

internal fun tokenPostMockerWithAuthDetails(
    configurationIds: List<CredentialConfigurationIdentifier>,
    validator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    TokenResponseTO.Success(
                        accessToken = UUID.randomUUID().toString(),
                        expiresIn = 3600,
                        authorizationDetails = authorizationDetails(configurationIds),
                    ),
                ),
                status = HttpStatusCode.OK,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        },
        requestValidator = validator,
    )

private fun authorizationDetails(
    configurationIds: List<CredentialConfigurationIdentifier>,
): Map<CredentialConfigurationIdentifier, List<CredentialIdentifier>> =
    configurationIds.map {
        it to listOf(
            CredentialIdentifier("${it.value}_1"),
            CredentialIdentifier("${it.value}_2"),
        )
    }.toMap()

internal fun singleIssuanceRequestMocker(
    credential: String = "",
    responseBuilder: HttpResponseDataBuilder = { defaultIssuanceResponseDataBuilder(it, credential) },
    requestValidator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/credentials", HttpMethod.Post),
        responseBuilder = responseBuilder,
        requestValidator = requestValidator,
    )

internal fun batchIssuanceRequestMocker(
    responseBuilder: HttpResponseDataBuilder,
    requestValidator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/credentials/batch", HttpMethod.Post),
        responseBuilder = responseBuilder,
        requestValidator = requestValidator,
    )

internal fun deferredIssuanceRequestMocker(
    responseBuilder: HttpResponseDataBuilder,
    requestValidator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/credentials/deferred", HttpMethod.Post),
        responseBuilder = responseBuilder,
        requestValidator = requestValidator,
    )

private fun MockRequestHandleScope.defaultIssuanceResponseDataBuilder(request: HttpRequestData?, credential: String): HttpResponseData {
    val textContent = request?.body as TextContent
    val issuanceRequest = Json.decodeFromString<JsonObject>(textContent.text)
    return if (issuanceRequest.get("proof") != null) {
        respond(
            content = """
                    {                                  
                      "credential": "$credential",
                      "notification_id": "valbQc6p55LS",
                      "c_nonce": "wlbQc6pCJp",
                      "c_nonce_expires_in": 86400
                    }
            """.trimIndent(),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    } else {
        respond(
            content = """
                    {
                        "error": "invalid_proof",
                        "c_nonce": "ERE%@^TGWYEYWEY",
                        "c_nonce_expires_in": 34
                    } 
            """.trimIndent(),
            status = HttpStatusCode.BadRequest,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }
}
