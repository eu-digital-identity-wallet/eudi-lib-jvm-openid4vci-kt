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

internal interface Format<M : CredentialMetadata.ByFormat, S : CredentialSupported, I : CredentialIssuanceRequest.SingleCredential> {

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

    fun mapRequestToTransferObject(
        credentialRequest: I,
    ): CredentialIssuanceRequestTO.SingleCredentialTO
}

internal object Formats {

    fun matchSupportedCredentialByTypeAndMapToDomain(
        format: String,
        jsonObject: JsonObject,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialMetadata =
        when (format) {
            MsoMdoc.FORMAT -> MsoMdoc.matchSupportedCredentialByTypeAndMapToDomain(jsonObject, issuerMetadata)
            SdJwtVc.FORMAT -> SdJwtVc.matchSupportedCredentialByTypeAndMapToDomain(jsonObject, issuerMetadata)
            W3CSignedJwt.FORMAT -> W3CSignedJwt.matchSupportedCredentialByTypeAndMapToDomain(jsonObject, issuerMetadata)
            W3CJsonLdSignedJwt.FORMAT -> W3CJsonLdSignedJwt.matchSupportedCredentialByTypeAndMapToDomain(jsonObject, issuerMetadata)
            W3CJsonLdDataIntegrity.FORMAT -> W3CJsonLdDataIntegrity.matchSupportedCredentialByTypeAndMapToDomain(
                jsonObject,
                issuerMetadata,
            )
            else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
        }

    fun decodeCredentialSupportedFromJsonObject(
        format: String,
        jsonObject: JsonObject,
    ): CredentialSupportedTO =
        when (format) {
            MsoMdoc.FORMAT -> MsoMdoc.decodeCredentialSupportedFromJsonObject(jsonObject)
            SdJwtVc.FORMAT -> SdJwtVc.decodeCredentialSupportedFromJsonObject(jsonObject)
            W3CSignedJwt.FORMAT -> W3CSignedJwt.decodeCredentialSupportedFromJsonObject(jsonObject)
            W3CJsonLdSignedJwt.FORMAT -> W3CJsonLdSignedJwt.decodeCredentialSupportedFromJsonObject(jsonObject)
            W3CJsonLdDataIntegrity.FORMAT -> W3CJsonLdDataIntegrity.decodeCredentialSupportedFromJsonObject(jsonObject)
            else -> throw IllegalArgumentException("Unsupported Credential format '$format'")
        }

    fun mapRequestToTransferObject(
        credentialRequest: CredentialIssuanceRequest.SingleCredential,
    ): CredentialIssuanceRequestTO.SingleCredentialTO =
        when (credentialRequest) {
            is MsoMdoc.Model.CredentialIssuanceRequest -> MsoMdoc.mapRequestToTransferObject(credentialRequest)
            is SdJwtVc.Model.CredentialIssuanceRequest -> SdJwtVc.mapRequestToTransferObject(credentialRequest)
            is W3CSignedJwt.Model.CredentialIssuanceRequest -> W3CSignedJwt.mapRequestToTransferObject(credentialRequest)
            is W3CJsonLdSignedJwt.Model.CredentialIssuanceRequest -> W3CJsonLdSignedJwt.mapRequestToTransferObject(credentialRequest)
            is W3CJsonLdDataIntegrity.Model.CredentialIssuanceRequest -> W3CJsonLdDataIntegrity.mapRequestToTransferObject(
                credentialRequest,
            )
        }

    fun matchSupportedCredentialByType(
        credentialMetadata: CredentialMetadata,
        issuerMetadata: CredentialIssuerMetadata,
    ): CredentialSupported =
        when (credentialMetadata) {
            is MsoMdoc.Model.CredentialMetadata -> MsoMdoc.matchSupportedCredentialByType(credentialMetadata, issuerMetadata)
            is SdJwtVc.Model.CredentialMetadata -> SdJwtVc.matchSupportedCredentialByType(credentialMetadata, issuerMetadata)
            is W3CSignedJwt.Model.CredentialMetadata -> W3CSignedJwt.matchSupportedCredentialByType(credentialMetadata, issuerMetadata)
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
