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
import eu.europa.ec.eudi.openid4vci.RequestMockerValidator
import eu.europa.ec.eudi.openid4vci.endsWith
import eu.europa.ec.eudi.openid4vci.getResourceAsText
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.util.*

internal fun oidcWellKnownMocker(): RequestMockerValidator = RequestMockerValidator(
    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
    responseBuilder = {
        respond(
            content = getResourceAsText("well-known/openid-credential-issuer_no_encryption.json"),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    },
    requestValidator = {},
)

internal fun authServerWellKnownMocker(): RequestMockerValidator = RequestMockerValidator(
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
    requestValidator = {},
)

internal fun parPostMocker(validator: (request: HttpRequestData) -> Unit): RequestMockerValidator =
    RequestMockerValidator(
        requestMatcher = endsWith("/ext/par/request", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    PushedAuthorizationRequestResponse.Success(
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

internal fun tokenPostMocker(validator: (request: HttpRequestData) -> Unit): RequestMockerValidator =
    RequestMockerValidator(
        requestMatcher = endsWith("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    AccessTokenRequestResponse.Success(
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

internal fun singleIssuanceRequestMocker(
    responseBuilder: HttpResponseDataBuilder,
    validator: (request: HttpRequestData) -> Unit,
): RequestMockerValidator =
    RequestMockerValidator(
        requestMatcher = endsWith("/credentials", HttpMethod.Post),
        responseBuilder = responseBuilder,
        requestValidator = validator,
    )

internal fun batchIssuanceRequestMocker(
    responseBuilder: HttpResponseDataBuilder,
    validator: (request: HttpRequestData) -> Unit,
): RequestMockerValidator =
    RequestMockerValidator(
        requestMatcher = endsWith("/credentials/batch", HttpMethod.Post),
        responseBuilder = responseBuilder,
        requestValidator = validator,
    )
