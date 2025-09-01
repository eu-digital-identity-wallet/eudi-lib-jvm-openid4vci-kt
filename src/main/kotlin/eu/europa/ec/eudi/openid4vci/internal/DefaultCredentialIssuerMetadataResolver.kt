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
package eu.europa.ec.eudi.openid4vci.internal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.jwk.AsymmetricJWK
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.proc.SingleKeyJWSKeySelector
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertChainUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.openid4vci.*
import eu.europa.ec.eudi.openid4vci.internal.http.CredentialIssuerMetadataJsonParser
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*

private const val CONTENT_TYPE_APPLICATION_JWT = "application/jwt"

internal class DefaultCredentialIssuerMetadataResolver(
    private val httpClient: HttpClient,
) : CredentialIssuerMetadataResolver {

    override suspend fun resolve(
        issuer: CredentialIssuerId,
        policy: IssuerMetadataPolicy,
    ): Result<CredentialIssuerMetadata> = runCatching {
        val wellKnownUrl = issuer.wellKnown()
        val json = when (policy) {
            IssuerMetadataPolicy.IgnoreSigned -> wellKnownUrl.requestUnsigned()
            is IssuerMetadataPolicy.RequireSigned -> wellKnownUrl.requestSigned(policy.issuerTrust, issuer)
            is IssuerMetadataPolicy.PreferSigned -> wellKnownUrl.requestPreferingSigned(policy.issuerTrust, issuer)
        }
        CredentialIssuerMetadataJsonParser.parseMetaData(json, issuer)
    }

    private suspend fun Url.requestUnsigned(): String {
        val response = getAcceptingContentTypes(ContentType.Application.Json.toString())
        val expectedHeaders = Headers.build {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        }
        require(response.headers == expectedHeaders) {
            "Credential issuer responded with invalid content type: " +
                "expected ${ContentType.Application.Json} but was ${response.headers[HttpHeaders.ContentType]}"
        }
        return response.body<String>()
    }

    private suspend fun Url.requestSigned(issuerTrust: IssuerTrust, issuer: CredentialIssuerId): String {
        val response = getAcceptingContentTypes(CONTENT_TYPE_APPLICATION_JWT)
        val expectedHeaders = Headers.build {
            append(HttpHeaders.ContentType, CONTENT_TYPE_APPLICATION_JWT)
        }
        ensure(response.headers == expectedHeaders) {
            CredentialIssuerMetadataError.MissingSignedMetadata()
        }
        return parseAndVerifySignedMetadata(response.body<String>(), issuerTrust, issuer)
            .getOrElse {
                throw CredentialIssuerMetadataError.InvalidSignedMetadata(it)
            }
    }

    private suspend fun Url.requestPreferingSigned(issuerTrust: IssuerTrust, issuer: CredentialIssuerId): String {
        val response = getAcceptingContentTypes(CONTENT_TYPE_APPLICATION_JWT, ContentType.Application.Json.toString())
        val contentType = response.headers[HttpHeaders.ContentType]

        requireNotNull(contentType) { "Credential issuer did not respond with a content type header" }

        return when (contentType) {
            CONTENT_TYPE_APPLICATION_JWT -> parseAndVerifySignedMetadata(
                jwt = response.body<String>(),
                issuerTrust = issuerTrust,
                issuer = issuer,
            ).getOrElse {
                throw CredentialIssuerMetadataError.InvalidSignedMetadata(it)
            }

            ContentType.Application.Json.toString() -> response.body<String>()

            else -> "Unexpected content type $contentType when retrieving issuer metadata."
        }
    }

    /**
     * Parses and verifies the signature of a Signed JWT that contains Credential Issuer Metadata.
     *
     * @param jwt the Signed JWT to parse and verify
     * @param issuerTrust trust anchor for the issuer of the signed metadata
     * @param issuer the id of the Credential Issuer whose signed metadata to parse
     */
    private suspend fun parseAndVerifySignedMetadata(
        jwt: String,
        issuerTrust: IssuerTrust,
        issuer: CredentialIssuerId,
    ): Result<String> = runCatching {
        val processor = DefaultJWTProcessor<SecurityContext>()
            .apply {
                jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(OpenId4VCISpec.SIGNED_METADATA_JWT_TYPE))
                jwsKeySelector = issuerTrust.keySelector(jwt)
                jwtClaimsSetVerifier =
                    DefaultJWTClaimsVerifier(
                        null,
                        JWTClaimsSet.Builder()
                            .subject(issuer.value.value.toExternalForm())
                            .build(),
                        setOf("iat", "sub"),
                    )
            }

        val claimsSet = processor.process(jwt, null)
        JSONObjectUtils.toJSONString(claimsSet.toJSONObject())
    }

    private suspend fun IssuerTrust.keySelector(jwt: String): JWSKeySelector<SecurityContext> {
        val signedJwt = SignedJWT.parse(jwt)
        val jwk = when (this) {
            is IssuerTrust.ByPublicKey -> jwk.toPublicJWK()

            is IssuerTrust.ByCertificateChain -> {
                val certChain = requireNotNull(signedJwt.header.x509CertChain) {
                    "missing 'x5c' header claim"
                }.let { X509CertChainUtils.parse(it) }

                require(certificateChainTrust.isTrusted(certChain)) {
                    "certificate chain in 'x5c' header claim is not trusted"
                }
                JWK.parse(certChain.first())
            }
        }
        require(jwk is AsymmetricJWK) {
            "Metadata signing key should be asymmetric."
        }

        val algorithm = signedJwt.header.algorithm
        return SingleKeyJWSKeySelector(algorithm, jwk.toPublicKey())
    }

    private suspend fun Url.getAcceptingContentTypes(vararg contentTypes: String): HttpResponse =
        try {
            val response = httpClient.get(this) {
                contentTypes.forEach {
                    accept(ContentType.parse(it))
                }
            }
            require(response.status.isSuccess()) {
                "Credential issuer responded with status code: ${response.status}"
            }
            response
        } catch (t: Throwable) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(t)
        }
}

internal fun CredentialIssuerId.wellKnown(): Url {
    val issuer = Url(this.value.toString())
    val pathSegment = buildString {
        append(OpenId4VCISpec.CREDENTIAL_ISSUER_WELL_KNOWN_PATH)
        val joinedSegments = issuer.segments.joinToString(separator = "/")
        if (joinedSegments.isNotBlank()) {
            append("/")
        }
        append(joinedSegments)
    }
    return URLBuilder(issuer).apply { path(pathSegment) }.build()
}
