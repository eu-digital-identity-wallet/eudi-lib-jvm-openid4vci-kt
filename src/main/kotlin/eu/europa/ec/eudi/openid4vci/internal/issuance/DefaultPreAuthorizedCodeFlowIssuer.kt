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
import java.time.Instant

class DefaultPreAuthorizedCodeFlowIssuer(
    val authorizer: IssuanceAuthorizer,
) : PreAuthorizationCodeFlowIssuer {

    override suspend fun authorize(
        preAuthorizedCode: String,
        pin: String,
    ): Result<PreAuthCodeFlowIssuance.Authorized> =
        Result.success(
            PreAuthCodeFlowIssuance.Authorized(
                authorizationCode = IssuanceAuthorization.PreAuthorizationCode(
                    preAuthorizedCode = preAuthorizedCode,
                    pin = pin,
                ),
            ),
        )

    @Suppress("ktlint")
    override suspend fun PreAuthCodeFlowIssuance.Authorized.placeAccessTokenRequest(): Result<PreAuthCodeFlowIssuance.AccessTokenRetrieved> =
        runCatching {
            val accessToken =
                authorizer.requestAccessTokenPreAuthFlow(
                    authorizationCode.preAuthorizedCode,
                    authorizationCode.pin
                ).getOrThrow()

            PreAuthCodeFlowIssuance.AccessTokenRetrieved(
                token = IssuanceAccessToken(accessToken),
            )
        }

    override suspend fun PreAuthCodeFlowIssuance.AccessTokenRetrieved.issueCredential(): Result<PreAuthCodeFlowIssuance.Issued> =
        Result.success(
            PreAuthCodeFlowIssuance.Issued(
                issuedAt = Instant.now(), // Will be the issuer's issuance date
                certificate = IssuedCertificate(
                    format = "mso_mdoc",
                    content = "TODO-IssuedCertificate.content",
                ),
            ),
        )
}
