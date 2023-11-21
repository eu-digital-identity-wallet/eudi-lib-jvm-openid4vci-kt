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
package eu.europa.ec.eudi.openid4vci.formats

import eu.europa.ec.eudi.openid4vci.CredentialIssuerMetadata
import eu.europa.ec.eudi.openid4vci.IssuanceResponseEncryptionSpec
import eu.europa.ec.eudi.openid4vci.Proof
import kotlinx.serialization.json.JsonObject

internal interface Format<
    in M : CredentialMetadata.ByFormat,
    in S : CredentialSupported,
    in I : CredentialIssuanceRequest.SingleCredential,
    > {

    fun matchSupportedCredentialByTypeAndMapToDomain(
        jsonObject: JsonObject,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialMetadata

    fun decodeCredentialSupportedFromJsonObject(
        jsonObject: JsonObject,
    ): CredentialSupportedTO

    fun matchSupportedCredentialByType(
        metadata: M,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported

    fun constructIssuanceRequest(
        supportedCredential: S,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<CredentialIssuanceRequest.SingleCredential>
}

internal object Formats {

    private val supported: Map<String, Format<*, *, *>> = mapOf(
        MsoMdoc.FORMAT to MsoMdoc,
        SdJwtVc.FORMAT to SdJwtVc,
        W3CSignedJwt.FORMAT to W3CSignedJwt,
        W3CJsonLdSignedJwt.FORMAT to W3CJsonLdSignedJwt,
        W3CJsonLdDataIntegrity.FORMAT to W3CJsonLdDataIntegrity,
    )

    private fun formatByName(format: String): Format<*, *, *> =
        supported[format] ?: throw IllegalArgumentException("Unsupported Credential format '$format'")

    fun matchSupportedCredentialByTypeAndMapToDomain(
        format: String,
        jsonObject: JsonObject,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialMetadata =
        formatByName(format).matchSupportedCredentialByTypeAndMapToDomain(jsonObject, issuerMetadata)

    fun decodeCredentialSupportedFromJsonObject(
        format: String,
        jsonObject: JsonObject,
    ): CredentialSupportedTO =
        formatByName(format).decodeCredentialSupportedFromJsonObject(jsonObject)

    fun matchSupportedCredentialByType(
        credentialMetadata: CredentialMetadata,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported =
        when (credentialMetadata) {
            is MsoMdoc.Model.CredentialMetadata -> MsoMdoc.matchSupportedCredentialByType(
                credentialMetadata,
                issuerMetadata,
            )

            is SdJwtVc.Model.CredentialMetadata -> SdJwtVc.matchSupportedCredentialByType(
                credentialMetadata,
                issuerMetadata,
            )

            is W3CSignedJwt.Model.CredentialMetadata -> W3CSignedJwt.matchSupportedCredentialByType(
                credentialMetadata,
                issuerMetadata,
            )

            is W3CJsonLdSignedJwt.Model.CredentialMetadata -> W3CJsonLdSignedJwt.matchSupportedCredentialByType(
                credentialMetadata,
                issuerMetadata,
            )

            is W3CJsonLdDataIntegrity.Model.CredentialMetadata -> W3CJsonLdDataIntegrity.matchSupportedCredentialByType(
                credentialMetadata,
                issuerMetadata,
            )

            else -> throw IllegalArgumentException("Unsupported Credential Metadata")
        }

    fun constructIssuanceRequest(
        supportedCredential: CredentialSupported,
        claimSet: ClaimSet?,
        proof: Proof?,
        responseEncryptionSpec: IssuanceResponseEncryptionSpec?,
    ): Result<CredentialIssuanceRequest.SingleCredential> =
        when (supportedCredential) {
            is MsoMdoc.Model.CredentialSupported -> MsoMdoc.constructIssuanceRequest(
                supportedCredential,
                claimSet,
                proof,
                responseEncryptionSpec,
            )

            is SdJwtVc.Model.CredentialSupported -> SdJwtVc.constructIssuanceRequest(
                supportedCredential,
                claimSet,
                proof,
                responseEncryptionSpec,
            )

            is W3CSignedJwt.Model.CredentialSupported -> W3CSignedJwt.constructIssuanceRequest(
                supportedCredential,
                claimSet,
                proof,
                responseEncryptionSpec,
            )

            is W3CJsonLdSignedJwt.Model.CredentialSupported -> W3CJsonLdSignedJwt.constructIssuanceRequest(
                supportedCredential,
                claimSet,
                proof,
                responseEncryptionSpec,
            )

            is W3CJsonLdDataIntegrity.Model.CredentialSupported -> W3CJsonLdDataIntegrity.constructIssuanceRequest(
                supportedCredential,
                claimSet,
                proof,
                responseEncryptionSpec,
            )
        }
}
