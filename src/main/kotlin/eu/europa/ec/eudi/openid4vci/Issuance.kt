/*
 *
 *  * Copyright (c) 2023 European Commission
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package eu.europa.ec.eudi.openid4vci

import eu.europa.ec.eudi.openid4vci.internal.AccessTokenRequestResponse
import eu.europa.ec.eudi.openid4vci.internal.AuthorizationActions
import eu.europa.ec.eudi.openid4vci.internal.PushedAuthorizationRequestResponse
import java.net.URL
import java.time.Instant

/**
 * AUTHORIZED CODE FLOW STATES
 */
sealed interface AuthCodeFlowIssuance {

    val initiatedAt: Instant

    data class Initiated(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
    ) : AuthCodeFlowIssuance

    data class ParRequested(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
        val getAuthorizationCodeURL: URL,
        val pkceVerifier: PKCEVerifier,
    ) : AuthCodeFlowIssuance

    data class Authorized(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
        val authorizationCode: IssuanceAuthorization.AuthorizationCode,
        val pkceVerifier: PKCEVerifier,
    ) : AuthCodeFlowIssuance

    data class AccessTokenRequested(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
        val token: CredentialIssuanceAccessToken,
    ) : AuthCodeFlowIssuance

    data class Issued(
        override val initiatedAt: Instant,
        val issuedAt: Instant,
        val certificate: IssuedCertificate,
    ) : AuthCodeFlowIssuance

    companion object {
        fun initFlow(
            credentialIssuerMetaData: CredentialIssuerMetaData,
            credentialOffer: CredentialOffer,
        ): Initiated =
            Initiated(
                initiatedAt = Instant.now(),
                credentialIssuerMetaData = credentialIssuerMetaData,
                credentialOffer = credentialOffer,
            )
    }
}

/**
 * AUTHORIZED CODE FLOW TRANSITIONS
 */

suspend fun AuthCodeFlowIssuance.Initiated.placePushedAuthorizationRequest(
    postPar: HttpFormPost<PushedAuthorizationRequestResponse>
): Result<AuthCodeFlowIssuance.ParRequested> = runCatching {

    // Get scoped credentials only
    val scopes = this.credentialOffer.credentials.filterIsInstance<Credential.ScopedCredential>()
        .map(Credential.ScopedCredential::scope)

    // Place PAR
    val (codeVerifier, authorizeRequestUrl) =
        AuthorizationActions.submitPushedAuthorizationRequest(
            this.credentialIssuerMetaData.authorizationServer, scopes, postPar
        ).getOrThrow()

    // Transition state
    AuthCodeFlowIssuance.ParRequested(
        initiatedAt = this.initiatedAt,
        credentialIssuerMetaData = this.credentialIssuerMetaData,
        credentialOffer = this.credentialOffer,
        getAuthorizationCodeURL = authorizeRequestUrl,
        pkceVerifier = PKCEVerifier(codeVerifier.codeVerifier, codeVerifier.codeVerifierMethod),
    )

}

suspend fun AuthCodeFlowIssuance.ParRequested.authorized(
    authorizationCode: String
): Result<AuthCodeFlowIssuance.Authorized> =
    Result.success(
        AuthCodeFlowIssuance.Authorized(
            initiatedAt = this.initiatedAt,
            credentialIssuerMetaData = this.credentialIssuerMetaData,
            credentialOffer = this.credentialOffer,
            authorizationCode = IssuanceAuthorization.AuthorizationCode(authorizationCode),
            pkceVerifier = this.pkceVerifier
        )
    )

suspend fun AuthCodeFlowIssuance.Authorized.placeAccessTokenRequest(
    getAccessToken: HttpFormPost<AccessTokenRequestResponse>
): Result<AuthCodeFlowIssuance.AccessTokenRequested> = runCatching {

    val accessToken =
        AuthorizationActions.accessTokenAuthFlow(
            this.credentialIssuerMetaData.authorizationServer,
            this.authorizationCode.authorizationCode,
            this.pkceVerifier.codeVerifier,
            getAccessToken
        ).getOrThrow()

    AuthCodeFlowIssuance.AccessTokenRequested(
        initiatedAt = this.initiatedAt,
        credentialIssuerMetaData = this.credentialIssuerMetaData,
        credentialOffer = this.credentialOffer,
        token = CredentialIssuanceAccessToken(accessToken)
    )
}

suspend fun AuthCodeFlowIssuance.AccessTokenRequested.requestVerifiableCredentialIssuance(
    token: CredentialIssuanceAccessToken,
    validateVerifiableCredential: (AuthCodeFlowIssuance.Issued) -> Boolean
): Result<AuthCodeFlowIssuance.Issued> = runCatching {

    AuthCodeFlowIssuance.Issued(
        initiatedAt = this.initiatedAt,
        issuedAt = Instant.now(), // Will be the issuer's issuance date
        certificate = IssuedCertificate(
            format = "mso_mdoc",
            content = "TODO-IssuedCertificate.content"
        )
    )
}

/**
 * PRE-AUTHORIZED CODE FLOW STATES
 */
sealed interface PreAuthCodeFlowIssuance {

    val initiatedAt: Instant

    data class Initiated(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer
    ) : PreAuthCodeFlowIssuance

    data class AccessTokenRequested(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
        val token: CredentialIssuanceAccessToken,
    ) : PreAuthCodeFlowIssuance

    data class Issued(
        override val initiatedAt: Instant,
        val issuedAt: Instant,
        val certificate: IssuedCertificate,
    ) : PreAuthCodeFlowIssuance

    companion object {
        fun initFlow(
            credentialIssuerMetaData: CredentialIssuerMetaData,
            credentialOffer: CredentialOffer,
        ): Initiated = Initiated(
            initiatedAt = Instant.now(),
            credentialIssuerMetaData = credentialIssuerMetaData,
            credentialOffer = credentialOffer
        )
    }
}

/**
 * PRE-AUTHORIZED CODE FLOW TRANSITIONS
 */

suspend fun PreAuthCodeFlowIssuance.Initiated.placeAccessTokenRequest(
    authorization: IssuanceAuthorization.PreAuthorizationCode,
    getAccessToken: HttpFormPost<AccessTokenRequestResponse>,
): Result<PreAuthCodeFlowIssuance.AccessTokenRequested> = runCatching {

    val accessToken =
        AuthorizationActions.accessTokenPreAuthFlow(
            this.credentialIssuerMetaData.authorizationServer,
            authorization.preAuthorizedCode,
            authorization.pin,
            getAccessToken
        ).getOrThrow()

    PreAuthCodeFlowIssuance.AccessTokenRequested(
        initiatedAt = this.initiatedAt,
        credentialIssuerMetaData = this.credentialIssuerMetaData,
        credentialOffer = this.credentialOffer,
        token = CredentialIssuanceAccessToken(accessToken)
    )
}

fun PreAuthCodeFlowIssuance.AccessTokenRequested.requestVerifiableCredentialIssuance(
    token: CredentialIssuanceAccessToken,
    validateVerifiableCredential: (PreAuthCodeFlowIssuance.Issued) -> Boolean
): Result<PreAuthCodeFlowIssuance.Issued> = runCatching  {

    PreAuthCodeFlowIssuance.Issued(
        initiatedAt = this.initiatedAt,
        issuedAt = Instant.now(), // Will be the issuer's issuance date
        certificate = IssuedCertificate(
            format = "mso_mdoc",
            content = "TODO-IssuedCertificate.content"
        )
    )
}

/**
 * AUTHORIZED CODE NO PAR FLOW STATES
 */
sealed interface AuthCodeFlowIssuanceNoPar {

    val initiatedAt: Instant

    data class Initiated(
        override val initiatedAt: Instant,
        val credentialIssuerMetaData: CredentialIssuerMetaData,
        val credentialOffer: CredentialOffer,
    ) : AuthCodeFlowIssuance

}
