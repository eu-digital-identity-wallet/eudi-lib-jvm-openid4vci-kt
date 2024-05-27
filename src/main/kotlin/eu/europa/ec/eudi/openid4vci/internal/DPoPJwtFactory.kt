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

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.dpop.DPoPUtils
import com.nimbusds.oauth2.sdk.id.JWTID
import com.nimbusds.openid.connect.sdk.Nonce
import eu.europa.ec.eudi.openid4vci.*
import io.ktor.client.request.*
import io.ktor.http.*
import java.net.URL
import java.time.Clock
import java.util.*
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory as NimbusDPoPProofFactory
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken as NimbusDPoPAccessToken

internal enum class Htm {
    GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE
}

/**
 * https://datatracker.ietf.org/doc/rfc9449/
 */
internal class DPoPJwtFactory(
    private val signer: PopSigner.Jwt,
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
        nonce: String? = null,
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
            nonce?.let { Nonce(it) },
        )
        SignedJWT(jwsHeader, jwtClaimsSet).apply { sign(signer.signer) }
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
        ): Result<DPoPJwtFactory?> = runCatching {
            val supportDPoPAlgs = oauthServerMetadata.dPoPJWSAlgs.orEmpty()
            val signerAlg = signer.algorithm
            if (supportDPoPAlgs.isNotEmpty()) {
                require(signerAlg in supportDPoPAlgs) {
                    "DPoP signer uses $signerAlg which is not dpop_signing_alg_values_supported=  $supportDPoPAlgs"
                }
                DPoPJwtFactory(signer, jtiByteLength, clock)
            } else null
        }
    }
}

internal fun HttpRequestBuilder.bearerOrDPoPAuth(
    factory: DPoPJwtFactory?,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken,
) {
    when (accessToken) {
        is AccessToken.Bearer -> {
            bearerAuth(accessToken)
        }

        is AccessToken.DPoP -> {
            if (factory != null) {
                dpop(factory, htu, htm, accessToken, nonce = null)
                dpopAuth(accessToken)
            } else {
                bearerAuth(AccessToken.Bearer(accessToken.accessToken))
            }
        }
    }
}

internal fun HttpRequestBuilder.dpop(
    factory: DPoPJwtFactory,
    htu: URL,
    htm: Htm,
    accessToken: AccessToken.DPoP?,
    nonce: String?,
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

internal const val DPoP = "DPoP"
