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
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import eu.europa.ec.eudi.openid4vci.internal.issuance.CredentialRequestTO
import eu.europa.ec.eudi.openid4vci.internal.issuance.DefaultIssuanceRequester
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorHttpClientFactory
import eu.europa.ec.eudi.openid4vci.internal.issuance.ktor.KtorIssuanceRequester
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

/**
 * Credential(s) issuance request
 */
sealed interface CredentialIssuanceRequest {

    /**
     * Models an issuance request for a batch of credentials
     */
    data class BatchCredentials(
        val credentialRequests: List<SingleCredential>,
    ) : CredentialIssuanceRequest

    /**
     * Models an issuance request for a single credential
     */
    sealed interface SingleCredential : CredentialIssuanceRequest {

        val format: String
        val proof: Proof?
        val credentialEncryptionJwk: JWK?
        val credentialResponseEncryptionAlg: JWEAlgorithm?
        val credentialResponseEncryptionMethod: EncryptionMethod?

        fun requiresEncryptedResponse(): Boolean =
            credentialResponseEncryptionAlg != null && credentialEncryptionJwk != null && credentialResponseEncryptionMethod != null

        /**
         * Issuance request for a credential of mso_mdoc format
         */
        class MsoMdocIssuanceRequest private constructor(
            val doctype: String,
            override val proof: Proof? = null,
            override val credentialEncryptionJwk: JWK? = null,
            override val credentialResponseEncryptionAlg: JWEAlgorithm? = null,
            override val credentialResponseEncryptionMethod: EncryptionMethod? = null,
            val claimSet: ClaimSet.MsoMdoc?,
        ) : SingleCredential {

            override val format: String = "mso_mdoc"

            companion object {
                operator fun invoke(
                    proof: Proof? = null,
                    credentialEncryptionJwk: JWK? = null,
                    credentialResponseEncryptionAlg: JWEAlgorithm? = null,
                    credentialResponseEncryptionMethod: EncryptionMethod? = null,
                    doctype: String,
                    claimSet: ClaimSet.MsoMdoc? = null,
                ): Result<MsoMdocIssuanceRequest> = runCatching {
                    var encryptionMethod = credentialResponseEncryptionMethod
                    if (credentialResponseEncryptionAlg != null && credentialResponseEncryptionMethod == null) {
                        encryptionMethod = EncryptionMethod.A256GCM
                    } else if (credentialResponseEncryptionAlg != null && credentialEncryptionJwk == null) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest("Encryption algorithm was provided but no encryption key")
                            .asException()
                    } else if (credentialResponseEncryptionAlg == null && credentialResponseEncryptionMethod != null) {
                        throw CredentialIssuanceError.InvalidIssuanceRequest(
                            "Credential response encryption algorithm must be specified if Credential " +
                                "response encryption method is provided",
                        ).asException()
                    }

                    MsoMdocIssuanceRequest(
                        proof = proof,
                        credentialEncryptionJwk = credentialEncryptionJwk,
                        credentialResponseEncryptionAlg = credentialResponseEncryptionAlg,
                        credentialResponseEncryptionMethod = encryptionMethod,
                        doctype = doctype,
                        claimSet = claimSet,
                    )
                }
            }
        }
    }
}

data class DeferredCredentialRequest(
    val transactionId: String,
    val token: IssuanceAccessToken,
)

data class CredentialIssuanceResponse(
    val credentialResponses: List<Result>,
    val cNonce: CNonce?,
) {
    sealed interface Result {
        data class Complete(
            val format: String,
            val credential: String,
        ) : Result

        data class Deferred(
            val transactionId: String,
        ) : Result
    }
}

sealed interface ClaimSet {
    data class MsoMdoc(
        val claims: Map<Namespace, Map<ClaimName, Claim>>,
    ) : ClaimSet

    data class SignedJwt(
        val claims: Map<ClaimName, Claim>,
    ) : ClaimSet

    data class JsonLdDataIntegrity(
        val claims: Map<ClaimName, Claim>,
    ) : ClaimSet

    data class JsonLdSignedJwt(
        val claims: Map<ClaimName, Claim>,
    ) : ClaimSet
}

/**
 * Interface that specifies the interaction with a Credentials Issuer required to handle the issuance of a credential
 */
interface IssuanceRequester {

    val issuerMetadata: CredentialIssuerMetadata

    /**
     * Method that submits a request to credential issuer for the issuance of single credential.
     *
     * @param request The single credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.SingleCredential,
    ): Result<CredentialIssuanceResponse>

    /**
     * Method that submits a request to credential issuer for the batch issuance of credentials.
     *
     * @param request The batch credential issuance request
     * @return credential issuer's response
     */
    suspend fun placeBatchIssuanceRequest(
        accessToken: IssuanceAccessToken,
        request: CredentialIssuanceRequest.BatchCredentials,
    ): Result<CredentialIssuanceResponse>

    /**
     * Method that submits a request to credential issuer's Deferred Credential Endpoint
     *
     * @param request The deferred credential request
     * @return response from issuer. Can be either positive if credential is issued or errored in case issuance is still pending
     */
    suspend fun placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        request: DeferredCredentialRequest,
    ): CredentialIssuanceResponse

    companion object {
        fun make(
            issuerMetadata: CredentialIssuerMetadata,
            postIssueRequest: HttpPost<CredentialRequestTO, CredentialIssuanceResponse, CredentialIssuanceResponse>,
        ): IssuanceRequester =
            DefaultIssuanceRequester(
                issuerMetadata = issuerMetadata,
                postIssueRequest = postIssueRequest,
            )
        fun ktor(
            issuerMetadata: CredentialIssuerMetadata,
            coroutineDispatcher: CoroutineDispatcher = Dispatchers.IO,
            httpClientFactory: KtorHttpClientFactory = KtorIssuanceRequester.DefaultFactory,
        ): IssuanceRequester =
            KtorIssuanceRequester(
                issuerMetadata = issuerMetadata,
                coroutineDispatcher = coroutineDispatcher,
                httpClientFactory = httpClientFactory,
            )
    }
}
