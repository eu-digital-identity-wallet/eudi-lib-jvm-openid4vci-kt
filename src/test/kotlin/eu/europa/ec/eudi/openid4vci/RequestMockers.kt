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

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import eu.europa.ec.eudi.openid4vci.IssuerMetadataVersion.*
import eu.europa.ec.eudi.openid4vci.internal.http.CNonceResponse
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialRequestTO
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

internal fun oiciWellKnownMocker(issuerMetadataVersion: IssuerMetadataVersion = ENCRYPTION_NOT_SUPPORTED): RequestMocker = RequestMocker(
    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
    responseBuilder = {
        val content = when (issuerMetadataVersion) {
            ENCRYPTION_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json")
            ENCRYPTION_NOT_SUPPORTED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_supported.json")
            ENCRYPTION_SUPPORTED_NOT_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_required.json")
            NO_NONCE_ENDPOINT -> getResourceAsText("well-known/openid-credential-issuer_no_nonce_endpoint.json")
            NO_SCOPES -> getResourceAsText("well-known/openid-credential-issuer_no_scopes.json")
            CONTAINS_DEPRECATED_METHOD -> getResourceAsText("well-known/openid-credential-issuer_contains_invalid_configuration.json")
            KEY_ATTESTATION_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_key_attestation_required.json")
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

enum class IssuerMetadataVersion {
    ENCRYPTION_REQUIRED,
    ENCRYPTION_NOT_SUPPORTED,
    ENCRYPTION_SUPPORTED_NOT_REQUIRED,
    NO_NONCE_ENDPOINT,
    NO_SCOPES,
    CONTAINS_DEPRECATED_METHOD,
    KEY_ATTESTATION_REQUIRED,
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

internal fun nonceEndpointMocker(
    nonceValue: String? = null,
    validator: (request: HttpRequestData) -> Unit = {},
): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/nonce", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    CNonceResponse(nonceValue ?: UUID.randomUUID().toString()),
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
    configurationIds.associateWith {
        listOf(
            CredentialIdentifier("${it.value}_1"),
            CredentialIdentifier("${it.value}_2"),
        )
    }

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
    return if (issuanceRequest["proof"] != null) {
        respond(
            content = """
                    {                                  
                      "credentials": [ {"credential": "$credential"} ],
                      "notification_id": "valbQc6p55LS"
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
                        "error": "invalid_proof"
                    } 
            """.trimIndent(),
            status = HttpStatusCode.BadRequest,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }
}

fun MockRequestHandleScope.respondToIssuanceRequestWithDeferredResponseDataBuilder(request: HttpRequestData?): HttpResponseData {
    val textContent = request?.body as TextContent
    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
    return if (issuanceRequest.proof != null) {
        respond(
            content = """
                    {                      
                      "transaction_id": "1234565768122"                     
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
                        "error": "invalid_proof"
                    } 
            """.trimIndent(),
            status = HttpStatusCode.BadRequest,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }
}

fun MockRequestHandleScope.defaultIssuanceResponseDataBuilder(
    credentialIsReady: Boolean,
    transactionIdIsValid: Boolean = true,
): HttpResponseData =
    if (credentialIsReady && transactionIdIsValid) {
        respond(
            content = """
                    {                     
                      "credentials": [ { "credential": "credential_content"} ]
                    }
            """.trimIndent(),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    } else {
        val error =
            if (!transactionIdIsValid) {
                "invalid_transaction_id "
            } else {
                "issuance_pending"
            }

        respond(
            content = """
                    {
                      "error": "$error",
                      "interval": 5
                    }
            """.trimIndent(),
            status = HttpStatusCode.BadRequest,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }

fun MockRequestHandleScope.encryptedResponseDataBuilder(
    request: HttpRequestData?,
    successResponseJsonProvider: () -> String,
): HttpResponseData {
    val (jwk, alg, enc) = extractEncryptionSpec(request)
    val responseJson = successResponseJsonProvider()
    return respond(
        content = encrypt(JWTClaimsSet.parse(responseJson), jwk, alg, enc).getOrThrow(),
        status = HttpStatusCode.OK,
        headers = headersOf(
            HttpHeaders.ContentType to listOf("application/jwt"),
        ),
    )
}

private fun extractEncryptionSpec(request: HttpRequestData?): Triple<JWK, JWEAlgorithm, EncryptionMethod> {
    val textContent = request?.body as TextContent
    val text = textContent.text
    val credentialResponseEncryption = if (text.contains("proofs")) {
        Json.decodeFromString<CredentialRequestTO>(text).credentialResponseEncryption
    } else {
        Json.decodeFromString<CredentialRequestTO>(text).credentialResponseEncryption
    }
    val jwk = JWK.parse(credentialResponseEncryption?.jwk.toString())
    val alg = JWEAlgorithm.parse(credentialResponseEncryption?.encryptionAlgorithm)
    val enc = EncryptionMethod.parse(credentialResponseEncryption?.encryptionMethod)
    return Triple(jwk, alg, enc)
}

fun encrypt(claimSet: JWTClaimsSet, jwk: JWK, alg: JWEAlgorithm, enc: EncryptionMethod): Result<String> =
    runCatching {
        randomRSAEncryptionKey(2048)
        val header =
            JWEHeader.Builder(alg, enc)
                .jwk(jwk.toPublicJWK())
                .keyID(jwk.keyID)
                .type(JOSEObjectType.JWT)
                .build()

        val jwt = EncryptedJWT(header, claimSet)
        val encrypter =
            when (jwk) {
                is RSAKey -> RSAEncrypter(jwk)
                is ECKey -> ECDHEncrypter(jwk)
                else -> error("unsupported 'kty': '${jwk.keyType.value}'")
            }

        jwt.encrypt(encrypter)
        jwt.serialize()
    }
