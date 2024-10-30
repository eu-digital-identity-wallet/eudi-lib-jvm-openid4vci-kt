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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils
import com.nimbusds.oauth2.sdk.id.JWTID
import io.ktor.client.request.*
import io.ktor.http.*
import java.net.URL
import java.time.Clock
import java.util.*
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory as NimbusDPoPProofFactory
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken as NimbusDPoPAccessToken
import com.nimbusds.openid.connect.sdk.Nonce as NimbusNonce

const val DPoP = "DPoP"

enum class Htm {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
}

/**
 * Factory class to generate DPoP JWTs to be added as a request header `DPoP` based on spec https://datatracker.ietf.org/doc/rfc9449/
 */
class DPoPJwtFactory(
    val signer: PopSigner.Jwt,
    private val jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
    private val clock: Clock,
) {
    init {
        require(jtiByteLength > 0) { "jtiByteLength must be greater than zero" }
    }

    private val publicJwk: JWK by lazy {
        val bk = signer.bindingKey
        require(bk is JwtBindingKey.Jwk) { "Only JWK binding key is supported" }
        bk.jwk
    }

    fun createDPoPJwt(
        htm: Htm,
        htu: URL,
        accessToken: AccessToken.DPoP? = null,
        nonce: Nonce? = null,
    ): Result<SignedJWT> = runCatching {
        val jwsHeader: JWSHeader = JWSHeader.Builder(signer.algorithm)
            .type(NimbusDPoPProofFactory.TYPE)
            .jwk(publicJwk)
            .build()
        val jwtClaimsSet = DPoPUtils.createJWTClaimsSet(
            jti(),
            htm.name,
            htu.toURI(),
            now(),
            accessToken?.let {
                NimbusDPoPAccessToken(it.accessToken)
            },
            nonce?.let { NimbusNonce(it.value) },
        )
        SignedJWT(jwsHeader, jwtClaimsSet).apply { sign(signer.jwsSigner) }
    }

    private fun now(): Date = Date.from(clock.instant())
    private fun jti(): JWTID = JWTID(jtiByteLength)

    companion object {

        /**
         * Tries to create a [DPoPJwtFactory] given a [signer] and the [oauthServerMetadata]
         * of the OAUTH2 or OIDC server.
         *
         * The factory will be created in case the server supports DPoP (this is indicated by a not empty array
         * ` dpop_signing_alg_values_supported` and in addition if the [signer] uses a supported algorithm
         *
         * @return
         * if the OAUTH2 server doesn't support DPoP result would be `Result.Success(null)`
         * if the OAUTH2 server supports DPoP and Signer uses a supported algorithm result would be success
         * Otherwise a failure will be returned
         *
         */
        fun createForServer(
            signer: PopSigner.Jwt,
            jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
            clock: Clock,
            oauthServerMetadata: CIAuthorizationServerMetadata,
        ): Result<DPoPJwtFactory?> =
            create(signer, jtiByteLength, clock, oauthServerMetadata.dPoPJWSAlgs.orEmpty())

        /**
         * Tries to create a [DPoPJwtFactory] given a [signer] and the
         * [supportedDPopAlgorithms]
         * of the OAUTH2 or OIDC server.
         *
         * The factory will be created in case the server supports DPoP (this is indicated by a not empty array
         * ` dpop_signing_alg_values_supported` and in addition if the [signer] uses a supported algorithm
         *
         * @return
         * if the OAUTH2 server doesn't support DPoP result would be `Result.Success(null)`
         * if the OAUTH2 server supports DPoP and Signer uses a supported algorithm result would be success
         * Otherwise a failure will be returned
         *
         */
        fun create(
            signer: PopSigner.Jwt,
            jtiByteLength: Int = NimbusDPoPProofFactory.MINIMAL_JTI_BYTE_LENGTH,
            clock: Clock,
            supportedDPopAlgorithms: List<JWSAlgorithm>,
        ): Result<DPoPJwtFactory?> = runCatching {
            val signerAlg = signer.algorithm
            if (supportedDPopAlgorithms.isNotEmpty()) {
                require(signerAlg in supportedDPopAlgorithms) {
                    "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportedDPopAlgorithms"
                }
                DPoPJwtFactory(signer, jtiByteLength, clock)
            } else null
        }
    }
}

/**
 * Utility method to be used to set properly the DPoP header on the request under construction, targeted on the URL passed as [htu].
 * Based on the passed [accessToken] DPoP header will be added if it is of type DPoP.
 */
fun HttpRequestBuilder.bearerOrDPoPAuth(
    factory: DPoPJwtFactory?,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken,
    nonce: Nonce?,
) {
    when (accessToken) {
        is AccessToken.Bearer -> {
            bearerAuth(accessToken)
        }
        is AccessToken.DPoP -> {
            if (factory != null) {
                dpop(factory, htu, htm, accessToken, nonce = nonce)
                dpopAuth(accessToken)
            } else {
                bearerAuth(AccessToken.Bearer(accessToken.accessToken, accessToken.expiresIn))
            }
        }
    }
}

/**
 * Adds header `DPoP` on the request under construction,  utilizing the passed [DPoPJwtFactory]
 */
fun HttpRequestBuilder.dpop(
    factory: DPoPJwtFactory,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken.DPoP?,
    nonce: Nonce?,
) {
    val jwt = factory.createDPoPJwt(htm, htu, accessToken, nonce).getOrThrow().serialize()
    header(DPoP, jwt)
}

private fun HttpRequestBuilder.dpopAuth(accessToken: AccessToken.DPoP) {
    header(HttpHeaders.Authorization, "$DPoP ${accessToken.accessToken}")
}

private fun HttpRequestBuilder.bearerAuth(accessToken: AccessToken.Bearer) {
    bearerAuth(accessToken.accessToken)
}
