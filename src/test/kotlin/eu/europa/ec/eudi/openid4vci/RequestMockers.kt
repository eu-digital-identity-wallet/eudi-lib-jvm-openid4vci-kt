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
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.Issuer.Companion.DefaultRequestEncryptionSpecFactory
import eu.europa.ec.eudi.openid4vci.Issuer.Companion.DefaultResponseEncryptionSpecFactory
import eu.europa.ec.eudi.openid4vci.IssuerMetadataVersion.*
import eu.europa.ec.eudi.openid4vci.internal.http.*
import eu.europa.ec.eudi.openid4vci.internal.issuanceEncryptionSpecs
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.util.*
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

internal fun credentialIssuerMetaDataHandler(
    id: CredentialIssuerId,
    resource: String,
    acceptContentTypes: List<String> = listOf("application/json"),
): RequestMocker = RequestMocker(
    match(id.metaDataUrl().value.toURI()),
    jsonResponse(resource, acceptContentTypes),
)

internal fun oauthMetaDataHandler(oauth2ServerUrl: HttpsUrl, oauth2MetaDataResource: String): RequestMocker = RequestMocker(
    match(oauthAuthorizationServerMetadataUrl(oauth2ServerUrl).value.toURI()),
    jsonResponse(oauth2MetaDataResource),
)

internal fun credentialIssuerMetadataWellKnownMocker(
    issuerMetadataVersion: IssuerMetadataVersion = ENCRYPTION_NOT_SUPPORTED,
): RequestMocker = RequestMocker(
    requestMatcher = endsWith("/.well-known/openid-credential-issuer", HttpMethod.Get),
    responseBuilder = {
        val content = issuerMetadataJsonContent(issuerMetadataVersion)
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
    ENCRYPTED_REQUEST_ONLY,
    NO_NONCE_ENDPOINT,
    NO_SCOPES,
    CONTAINS_DEPRECATED_METHOD,
    KEY_ATTESTATION_REQUIRED,
    ATTESTATION_PROOF_SUPPORTED,
}

internal fun issuerMetadataJsonContent(issuerMetadataVersion: IssuerMetadataVersion): String = when (issuerMetadataVersion) {
    ENCRYPTION_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encrypted_responses.json")
    ENCRYPTION_NOT_SUPPORTED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_supported.json")
    ENCRYPTION_SUPPORTED_NOT_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_encryption_not_required.json")
    ENCRYPTED_REQUEST_ONLY -> getResourceAsText("well-known/openid-credential-issuer_encrypted_requests_only.json")
    NO_NONCE_ENDPOINT -> getResourceAsText("well-known/openid-credential-issuer_no_nonce_endpoint.json")
    NO_SCOPES -> getResourceAsText("well-known/openid-credential-issuer_no_scopes.json")
    CONTAINS_DEPRECATED_METHOD -> getResourceAsText("well-known/openid-credential-issuer_contains_invalid_configuration.json")
    KEY_ATTESTATION_REQUIRED -> getResourceAsText("well-known/openid-credential-issuer_key_attestation_required.json")
    ATTESTATION_PROOF_SUPPORTED -> getResourceAsText("well-known/openid-credential-issuer_attestation_proof_supported.json")
}

enum class AuthServerMetadataVersion {
    FULL,
    NO_DPOP,
}

internal fun authServerWellKnownMocker(
    metadataVersion: AuthServerMetadataVersion = AuthServerMetadataVersion.FULL,
): RequestMocker = RequestMocker(
    requestMatcher = { request ->
        request.url.encodedPath.contains("/.well-known/oauth-authorization-server") && request.method == HttpMethod.Get
    },
    responseBuilder = {
        val content = when (metadataVersion) {
            AuthServerMetadataVersion.FULL -> getResourceAsText("well-known/openid-configuration.json")
            AuthServerMetadataVersion.NO_DPOP -> getResourceAsText("well-known/openid-configuration_no_dpop.json")
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

internal fun tokenPostMocker(dpopAccessToken: Boolean = false, validator: (request: HttpRequestData) -> Unit = {}): RequestMocker =
    RequestMocker(
        requestMatcher = endsWith("/token", HttpMethod.Post),
        responseBuilder = {
            respond(
                content = Json.encodeToString(
                    TokenResponseTO.Success(
                        accessToken = UUID.randomUUID().toString(),
                        expiresIn = 3600,
                        tokenType = if (dpopAccessToken) "DPoP" else null,
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
    dPopNonceValue: String? = null,
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
                    "DPoP-Nonce" to listOf(dPopNonceValue ?: UUID.randomUUID().toString()),
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
    return if (issuanceRequest["proofs"] != null) {
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

fun MockRequestHandleScope.respondToIssuanceRequestWithDeferredResponseDataBuilder(
    request: HttpRequestData?,
    transactionId: TransactionId? = null,
): HttpResponseData {
    val textContent = request?.body as TextContent
    val issuanceRequest = Json.decodeFromString<CredentialRequestTO>(textContent.text)
    return if (issuanceRequest.proofs != null) {
        respond(
            content = """
                    {                      
                      "transaction_id": "${transactionId?.value ?: UUID.randomUUID().toString()}",
                      "interval": 12345
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
    transactionId: TransactionId? = null,
    transactionIdIsValid: Boolean = true,
): HttpResponseData =
    if (transactionIdIsValid) {
        if (credentialIsReady) {
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
            respond(
                content = """
                        {
                          "transaction_id": "${transactionId?.value ?: UUID.randomUUID().toString()}",
                          "interval": 12345
                        }
                """.trimIndent(),
                status = HttpStatusCode.Accepted,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                ),
            )
        }
    } else {
        respond(
            content = """
                    {
                      "error": "invalid_transaction_id"
                    }
            """.trimIndent(),
            status = HttpStatusCode.BadRequest,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }

fun MockRequestHandleScope.encryptionAwareResponseDataBuilder(
    request: HttpRequestData?,
    issuerMetadataVersion: IssuerMetadataVersion,
    successResponseJsonProvider: () -> String,
): HttpResponseData {
    val responseEncryption = extractResponseEncryptionSpec(request, issuerMetadataVersion)
    val responseJson = successResponseJsonProvider()
    return responseEncryption?.let {
        val (jwk, alg, enc) = responseEncryption
        respond(
            content = encypt(JWTClaimsSet.parse(responseJson), jwk, alg, enc).getOrThrow(),
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/jwt"),
            ),
        )
    } ?: run {
        respond(
            content = responseJson,
            status = HttpStatusCode.OK,
            headers = headersOf(
                HttpHeaders.ContentType to listOf("application/json"),
            ),
        )
    }
}

private fun extractResponseEncryptionSpec(
    request: HttpRequestData?,
    issuerMetadataVersion: IssuerMetadataVersion,
): Triple<JWK, JWEAlgorithm, EncryptionMethod>? {
    val textContent = request?.body as TextContent
    val text = textContent.text

    val contentType = textContent.contentType.toString()
    val credentialResponseEncryption = when (contentType) {
        "application/json" -> {
            try {
                Json.decodeFromString<CredentialRequestTO>(text).credentialResponseEncryption
            } catch (_: Exception) {
                Json.decodeFromString<DeferredRequestTO>(text).credentialResponseEncryption
            }
        }
        "application/jwt" -> {
            val requestDecrypter = RequestDecrypter(issuerMetadataVersion)
            try {
                requestDecrypter.decrypt<CredentialRequestTO>(request).credentialResponseEncryption
            } catch (_: Exception) {
                requestDecrypter.decrypt<DeferredRequestTO>(request).credentialResponseEncryption
            }
        }
        else -> fail("Unsupported content type: $contentType")
    }

    return credentialResponseEncryption?.let {
        val jwk = JWK.parse(credentialResponseEncryption.jwk.toString())
        val alg = JWEAlgorithm.parse(jwk.algorithm.name)
        val enc = EncryptionMethod.parse(credentialResponseEncryption.encryptionMethod)
        Triple(jwk, alg, enc)
    }
}

internal fun encypt(claimSet: JWTClaimsSet, jwk: JWK, alg: JWEAlgorithm, enc: EncryptionMethod): Result<String> =
    runCatching {
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

internal inline fun <reified RequestTO> encryptionAwareRequestValidator(
    request: HttpRequestData,
    issuerMetadataVersion: IssuerMetadataVersion,
    walletConfig: OpenId4VCIConfig = OpenId4VCIConfiguration,
    validateRequest: (RequestTO) -> Unit = {},
) {
    val requestDecrypter = RequestDecrypter(issuerMetadataVersion, walletConfig)
    val decrypted = requestDecrypter.decrypt<RequestTO>(request)
    validateRequest(decrypted)
}

internal fun decrypt(encrypted: String, alg: JWEAlgorithm, enc: EncryptionMethod, jwkSet: JWKSet): Result<JWTClaimsSet> =
    runCatching {
        val jwtProcessor = DefaultJWTProcessor<SecurityContext>().apply {
            jweKeySelector = JWEDecryptionKeySelector(
                alg, enc,
                ImmutableJWKSet(jwkSet),
            )
        }
        jwtProcessor.process(encrypted, null)
    }

internal class RequestDecrypter(
    val issuerMetadataVersion: IssuerMetadataVersion,
    val walletConfig: OpenId4VCIConfig = OpenId4VCIConfiguration,
) {

    private val credentialRequestEncryption: CredentialRequestEncryption
    private val issuanceEncryptionSpecs: IssuanceEncryptionSpecs

    init {
        val issuerMetadataJsonContent = issuerMetadataJsonContent(issuerMetadataVersion)
        val issuerId = CredentialIssuerId("https://credential-issuer.example.com").getOrThrow()
        val metadata = CredentialIssuerMetadataJsonParser.parseMetaData(issuerMetadataJsonContent, issuerId)
        credentialRequestEncryption = metadata.credentialRequestEncryption

        issuanceEncryptionSpecs = issuanceEncryptionSpecs(
            encryptionSupportConfig = walletConfig.encryptionSupportConfig,
            credentialRequestEncryption = metadata.credentialRequestEncryption,
            credentialResponseEncryption = metadata.credentialResponseEncryption,
            requestEncryptionSpecFactory = DefaultRequestEncryptionSpecFactory,
            responseEncryptionSpecFactory = DefaultResponseEncryptionSpecFactory,
        ).getOrElse {
            fail(
                "Failed to create encryption specs based on issuer metadata: $issuerMetadataVersion and " +
                    "wallet encryption config: ${walletConfig.encryptionSupportConfig}",
            )
        }
    }

    inline fun <reified T> decrypt(request: HttpRequestData): T {
        val textContent = request.body as TextContent
        val contentType = textContent.contentType.toString()

        when (credentialRequestEncryption) {
            is CredentialRequestEncryption.Required -> {
                assertTrue("Issuer expects encrypted requests. Content-Type header must be 'application/jwt'") {
                    contentType == "application/jwt"
                }
            }

            CredentialRequestEncryption.NotSupported -> {
                assertTrue("Issuer does not support encrypted requests but request is encrypted.") {
                    contentType == "application/json"
                }
            }

            is CredentialRequestEncryption.SupportedNotRequired -> Unit
        }

        return when (contentType) {
            "application/jwt" -> {
                val spec = issuanceEncryptionSpecs.requestEncryptionSpec
                assertNotNull(spec, "Request encryption spec expected")
                val jwtClaimSet =
                    decrypt(textContent.text, spec.algorithm, spec.encryptionMethod, loadKeySet())
                        .getOrThrow()
                Json.decodeFromString<T>(JSONObjectUtils.toJSONString(jwtClaimSet.toJSONObject()))
            }

            "application/json" -> Json.decodeFromString<T>(textContent.text)

            else -> fail("Unsupported content type: $contentType")
        }
    }

    fun loadKeySet(): JWKSet =
        JWKSet.load(getResourceAsFile("eu/europa/ec/eudi/openid4vci/internal/request_encryption_keyset.json"))
}
