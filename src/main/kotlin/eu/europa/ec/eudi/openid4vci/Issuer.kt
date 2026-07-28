/*
 * Copyright (c) 2023-2026 European Commission
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

import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import eu.europa.ec.eudi.openid4vci.internal.*
import eu.europa.ec.eudi.openid4vci.internal.http.*
import io.ktor.client.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import java.net.URI
import java.time.Instant

/**
 * Represents the result of an issuer resolution process which can either be successful or a failure.
 */
sealed interface IssuerResolutionResult {

    /**
     * Represents a successful outcome of the issuer resolution process.
     *
     * @property issuer The resolved issuer from the process.
     * @property policyViolationWarning A list of warnings related to policy violations
     * during the registration certificate policy processing. Defaults to an empty list.
     */
    data class Success(
        val issuer: Issuer,
        val policyViolationWarning: List<RegistrationCertificatePolicy.PolicyViolation> = emptyList(),
    ) : IssuerResolutionResult

    /**
     * Represents a failed outcome of the issuer resolution process.
     *
     * This class encapsulates details about the failure that occurred during the issuer resolution process.
     * The failure is represented by an associated exception, providing additional context about the error.
     *
     * @property exception The exception encountered during the issuer resolution process.
     */
    data class Failure(
        val exception: Throwable,
    ) : IssuerResolutionResult
}

fun IssuerResolutionResult.getIssuerOrThrow(): Issuer =
    when (this) {
        is IssuerResolutionResult.Success -> this.issuer
        is IssuerResolutionResult.Failure -> throw exception
    }

/**
 * Entry point to the issuance library
 *
 * Provides the following capabilities
 * - [AuthorizeIssuance]
 * - [RefreshAccessToken]
 * - [RequestIssuance]
 * - [QueryForDeferredCredential]
 * - [NotifyIssuer]
 *
 * [Issuer] lifecycle is bound to serve a single [credentialOffer]
 *
 * Typically, one of the factory methods found on the companion object can be used to get an instance of [Issuer].
 *
 */
interface Issuer :
    AuthorizeIssuance,
    RefreshAccessToken,
    RequestIssuance,
    QueryForDeferredCredential,
    NotifyIssuer {

    val credentialOffer: CredentialOffer

    /**
     * A convenient method for obtaining a [DeferredIssuanceContext], in case of a deferred issuance
     * that wallet wants to query again at a later time, using [DeferredIssuer].
     *
     * Typically, wallet should store this [DeferredIssuanceContext] and [use it][DeferredIssuer] at a later time
     *
     * @receiver the state of issuance
     * @param deferredCredential the transaction id returned by the issuer
     * @return the context that would be necessary to instantiate a [DeferredIssuer]
     */
    fun AuthorizedRequest.deferredContext(deferredCredential: SubmissionOutcome.Deferred): DeferredIssuanceContext

    companion object {

        /**
         * Fetches & validates the issuer's [CredentialIssuerMetadata] and list
         * of [CIAuthorizationServerMetadata][OAUTH2 server(s) metadata] used by the issuer
         *
         * @param httpClient The client to fetch the metadata
         * @param credentialIssuerId The id of the credential issuer
         * @param policy policy for signed metadata
         *
         * @return the issuer's [CredentialIssuerMetadata] and list
         *  of [CIAuthorizationServerMetadata][OAUTH2 server(s) metadata] used by the issuer
         */
        suspend fun metaData(
            httpClient: HttpClient,
            credentialIssuerId: CredentialIssuerId,
            policy: IssuerMetadataPolicy,
        ): Pair<CredentialIssuerMetadata, List<CIAuthorizationServerMetadata>> = coroutineScope {
            with(httpClient) {
                val issuerMetadata = run {
                    val resolver = DefaultCredentialIssuerMetadataResolver(httpClient)
                    resolver.resolve(credentialIssuerId, policy).getOrThrow()
                }
                val authorizationServersMetadata =
                    issuerMetadata.authorizationServers.distinct().map { authServerUrl ->
                        async {
                            val resolver = DefaultAuthorizationServerMetadataResolver(httpClient)
                            resolver.resolve(authServerUrl).getOrThrow()
                        }
                    }.awaitAll()

                issuerMetadata to authorizationServersMetadata
            }
        }

        /**
         * Factory method for creating an instance of [Issuer] based on a resolved and validated credential offer.
         *
         * @param config wallet's configuration options
         * @param credentialOffer the offer for which the issuer is being created
         * @param httpClient an http client, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         * @param requestEncryptionSpecFactory a factory method to generate the issuance request encryption
         *
         * @return if wallet's [config] can satisfy the requirements of [credentialOffer] an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun make(
            config: OpenId4VCIConfig,
            credentialOffer: CredentialOffer,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
        ): IssuerResolutionResult = runCatchingCancellable {
            val authorizationServer = HttpsUrl(credentialOffer.authorizationServerMetadata.issuer.value).getOrThrow()

            val provisionClientAttestation =
                when (val clientAuthentication = config.clientAuthentication) {
                    is ClientAuthentication.AttestationBased -> {
                        clientAuthentication.provisionClientAttestation.ensureSupportedByAuthorizationServer(
                            credentialOffer.authorizationServerMetadata,
                        )

                        clientAttestation(
                            authorizationServer,
                            credentialOffer.credentialIssuerMetadata.preferredClientStatusPeriod,
                            clientAuthentication,
                        )
                    }

                    is ClientAuthentication.None -> {
                        { null }
                    }
                }

            val dPoPConfig = when (val dPoPUsage = config.dPoPUsage) {
                DPoPUsage.Never -> null
                is DPoPUsage.IfSupported -> dPoPUsage.value
                is DPoPUsage.Required -> {
                    checkNotNull(credentialOffer.dPoPCtx) {
                        "Client requires the usage of DPoP, but the Authorization Server does not support DPoP " +
                            "or the signing algorithm supported by the Client"
                    }
                    dPoPUsage.value
                }
            }

            val provisionDPoPJwtFactory =
                if (null != credentialOffer.dPoPCtx) {
                    checkNotNull(dPoPConfig) { "dPoPConfig is required when using DPoP" }
                    dPoPJwtFactory(config.clock, authorizationServer, dPoPConfig)
                } else {
                    { null }
                }

            val authorizationEndpointClient =
                credentialOffer.authorizationServerMetadata
                    .authorizationEndpointURI
                    ?.let {
                        AuthorizationEndpointClient(
                            credentialOffer.credentialIssuerIdentifier,
                            credentialOffer.authorizationServerMetadata,
                            config,
                            provisionDPoPJwtFactory,
                            provisionClientAttestation,
                            httpClient,
                        )
                    }

            val tokenEndpointClient =
                TokenEndpointClient(
                    credentialOffer.credentialIssuerIdentifier,
                    credentialOffer.authorizationServerMetadata,
                    config,
                    provisionDPoPJwtFactory,
                    provisionClientAttestation,
                    httpClient,
                )

            val authorizeIssuance =
                AuthorizeIssuanceImpl(
                    credentialOffer,
                    config,
                    authorizationEndpointClient,
                    tokenEndpointClient,
                )

            val requestIssuance = run {
                val credentialEndpointClient =
                    CredentialEndpointClient(
                        credentialOffer.credentialIssuerMetadata.credentialEndpoint,
                        provisionDPoPJwtFactory,
                        httpClient,
                    )
                val nonceEndpointClient = credentialOffer.credentialIssuerMetadata.nonceEndpoint?.let {
                    NonceEndpointClient(
                        credentialOffer.credentialIssuerMetadata.nonceEndpoint,
                        httpClient,
                    )
                }
                RequestIssuanceImpl(
                    credentialOffer,
                    config,
                    credentialEndpointClient,
                    nonceEndpointClient,
                    credentialOffer.credentialIssuerMetadata.batchCredentialIssuance,
                    credentialOffer.exchangeEncryptionSpecification,
                )
            }

            val refreshAccessToken = RefreshAccessTokenImpl(tokenEndpointClient)

            val queryForDeferredCredential =
                when (val deferredEndpoint = credentialOffer.credentialIssuerMetadata.deferredCredentialEndpoint) {
                    null -> QueryForDeferredCredential.NotSupported
                    else -> {
                        val deferredEndPointClient =
                            DeferredEndPointClient(deferredEndpoint, provisionDPoPJwtFactory, httpClient)
                        QueryForDeferredCredential(
                            config.clock,
                            refreshAccessToken,
                            deferredEndPointClient,
                            credentialOffer.exchangeEncryptionSpecification,
                        )
                    }
                }

            val notifyIssuer =
                when (val notificationEndpoint = credentialOffer.credentialIssuerMetadata.notificationEndpoint) {
                    null -> NotifyIssuer.NoOp
                    else -> {
                        val notificationEndPointClient =
                            NotificationEndPointClient(notificationEndpoint, provisionDPoPJwtFactory, httpClient)
                        NotifyIssuer(notificationEndPointClient)
                    }
                }

            val policyViolationWarnings = config.registrationCertificatePolicy?.let { policy ->
                with(RegistrationCertificatePolicyEvaluator(policy)) {
                    val authorization = evaluate(credentialOffer)
                    when (authorization) {
                        is RegistrationCertificatePolicy.Authorization.Granted -> authorization.warnings
                        is RegistrationCertificatePolicy.Authorization.NotGranted ->
                            throw AuthorizationPolicyValidationError.AuthorizationPolicyNotMet(authorization.error)
                    }
                }
            }

            val issuer = object :
                Issuer,
                AuthorizeIssuance by authorizeIssuance,
                RefreshAccessToken by refreshAccessToken,
                RequestIssuance by requestIssuance,
                QueryForDeferredCredential by queryForDeferredCredential,
                NotifyIssuer by notifyIssuer {
                override val credentialOffer: CredentialOffer
                    get() = credentialOffer

                override fun AuthorizedRequest.deferredContext(
                    deferredCredential: SubmissionOutcome.Deferred,
                ): DeferredIssuanceContext {
                    val credentialIssuerMetadata = credentialOffer.credentialIssuerMetadata
                    val authorizationServerMetadata = credentialOffer.authorizationServerMetadata

                    val deferredEndpoint =
                        checkNotNull(credentialIssuerMetadata.deferredCredentialEndpoint?.value) {
                            "Missing deferred credential endpoint"
                        }

                    val challengeEndpoint = authorizationServerMetadata.challengeEndpointURI?.toURL()

                    val tokenEndpoint =
                        checkNotNull(authorizationServerMetadata.tokenEndpointURI?.toURL()) {
                            "Missing token endpoint"
                        }

                    return DeferredIssuanceContext(
                        DeferredIssuerConfig(
                            credentialIssuerId = credentialOffer.credentialIssuerIdentifier,
                            clientAuthentication = config.clientAuthentication,
                            deferredEndpoint = deferredEndpoint,
                            authorizationServerId = URI(authorizationServerMetadata.issuer.value).toURL(),
                            challengeEndpoint = challengeEndpoint,
                            tokenEndpoint = tokenEndpoint,
                            requestEncryptionSpec = credentialOffer.exchangeEncryptionSpecification.requestEncryptionSpec,
                            responseEncryptionParams = credentialOffer.exchangeEncryptionSpecification.responseEncryptionSpec?.let {
                                it.encryptionMethod to it.compressionAlgorithm
                            },
                            dPoPConfig =
                                if (null != credentialOffer.dPoPCtx) dPoPConfig
                                else null,
                            clock = config.clock,
                        ),
                        AuthorizedTransaction(this@deferredContext, deferredCredential.transactionId),
                    )
                }
            }

            policyViolationWarnings to issuer
        }.fold(
            onSuccess = { IssuerResolutionResult.Success(it.second, it.first ?: emptyList()) },
            onFailure = { IssuerResolutionResult.Failure(it) },
        )

        /**
         * Factory method for creating an instance of [Issuer] based on a credential offer URI.
         * Method will try to first resolve the [credentialOfferUri] into a [CredentialOffer]
         * proceed with the creation of the [Issuer]
         *
         * @param config wallet's configuration options
         * @param credentialOfferUri the credential offer uri to be resolved
         * @param httpClient an http client, used while interacting with issuer
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of the resolved credentialOffer an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun make(
            config: OpenId4VCIConfig,
            credentialOfferUri: String,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
        ): IssuerResolutionResult = runCatchingCancellable {
            val credentialOffer = CredentialOffer.resolve(
                requestEncryptionSpecFactory,
                responseEncryptionSpecFactory,
                httpClient,
                config,
                credentialOfferUri,
            ).getOrThrow()
            make(
                config,
                credentialOffer,
                httpClient,
                requestEncryptionSpecFactory,
                responseEncryptionSpecFactory,
            )
        }.fold(
            onSuccess = { it },
            onFailure = { IssuerResolutionResult.Failure(it) },
        )

        /**
         * Factory method for creating an instance of [Issuer] with a credential offer (Wallet initiated)
         * This requires out-of-band knowledge of [issuer][credentialIssuerId] and one or more
         * [credentialConfigurationIdentifiers].
         *
         * This is equivalent to instantiating a credential offer, using authorization code grant,
         * without `issuer_state`.
         *
         * @param config wallet's configuration options
         * @param credentialIssuerId the id of the credential issuer
         * @param credentialConfigurationIdentifiers a list of credential configuration identifiers
         * @param httpClient an http client, used while interacting with issuer
         * @param requestEncryptionSpecFactory a factory method to generate the issuance request encryption
         * @param responseEncryptionSpecFactory a factory method to generate the issuance response encryption
         *
         * @return if wallet's [config] can satisfy the requirements of credential issuer, an [Issuer] will be
         * created. Otherwise, there would be a failed result
         */
        suspend fun makeWalletInitiated(
            config: OpenId4VCIConfig,
            credentialIssuerId: CredentialIssuerId,
            credentialConfigurationIdentifiers: List<CredentialConfigurationIdentifier>,
            httpClient: HttpClient,
            requestEncryptionSpecFactory: RequestEncryptionSpecFactory = RequestEncryptionSpecFactory.DEFAULT,
            responseEncryptionSpecFactory: ResponseEncryptionSpecFactory = ResponseEncryptionSpecFactory.DEFAULT,
        ): IssuerResolutionResult = runCatchingCancellable {
            val metadata = metaData(httpClient, credentialIssuerId, config.issuerMetadataPolicy)
            val authorizationServer = metadata.first.authorizationServers.first()

            val credentialOffer = CredentialOffer.walletInitiated(
                requestEncryptionSpecFactory,
                responseEncryptionSpecFactory,
                httpClient,
                config,
                credentialIssuerId,
                credentialConfigurationIdentifiers,
                authorizationServer,
            ).getOrThrow()

            make(
                config,
                credentialOffer,
                httpClient,
                requestEncryptionSpecFactory,
                responseEncryptionSpecFactory,
            )
        }.fold(
            onSuccess = { it },
            onFailure = { IssuerResolutionResult.Failure(it) },
        )
    }
}

internal fun ProvisionClientAttestation.ensureSupportedByAuthorizationServer(
    authorizationServerMetadata: CIAuthorizationServerMetadata,
) {
    val supportedAuthenticationMethods = authorizationServerMetadata.tokenEndpointAuthMethods.orEmpty()
    val authenticationMethod =
        ClientAuthenticationMethod(AttestationBasedClientAuthenticationSpec.ATTESTATION_JWT_CLIENT_AUTHENTICATION_METHOD)
    require(authenticationMethod in supportedAuthenticationMethods) {
        "${authenticationMethod.value} Authentication Method not supported by Authorization Server"
    }

    val supportedClientAttestationJWSAlgs = authorizationServerMetadata.clientAttestationJWSAlgs.orEmpty()
    val clientAttestationJWSAlg = algorithm.toNimbus()
    require(clientAttestationJWSAlg in supportedClientAttestationJWSAlgs) {
        "${clientAttestationJWSAlg.name} Client Attestation JWS Algorithm not supported by Authorization Server"
    }

    val supportedClientAttestationPOPJWSAlgs = authorizationServerMetadata.clientAttestationPOPJWSAlgs.orEmpty()
    val clientAttestationPOPJWSAlg = popAlgorithm.toNimbus()
    require(clientAttestationPOPJWSAlg in supportedClientAttestationPOPJWSAlgs) {
        "${clientAttestationPOPJWSAlg.name} Client Attestation POP JWS Algorithm not supported by Authorization Server"
    }
}

/**
 * Utility function used to verify a [provisioned ClientAttestation and its PoP Signer][ProvisionClientAttestation.Provisioned]
 * is active and according to the specification advertised by the [this].
 */
fun ProvisionClientAttestation.ensureValid(now: Instant, provisioned: ProvisionClientAttestation.Provisioned) {
    val clientAttestation = SignedJWT.parse(provisioned.clientAttestation.value)

    check(algorithm.toNimbus() == clientAttestation.header.algorithm) {
        "Client Attestation JWT algorithm mismatch: expected ${algorithm.name}, got ${clientAttestation.header.algorithm.name}"
    }

    if (null != clientAttestation.jwtClaimsSet.notBeforeTime) {
        check(now >= clientAttestation.jwtClaimsSet.notBeforeTime.toInstant()) { "Client Attestation JWT is not active yet" }
    }

    if (null != clientAttestation.jwtClaimsSet.expirationTime) {
        check(now < clientAttestation.jwtClaimsSet.expirationTime.toInstant()) { "Client Attestation JWT is expired" }
    }

    val popSignerAlgorithm = provisioned.popSigner.javaAlgorithm.toJoseAlg()
    check(popAlgorithm.toNimbus() == popSignerAlgorithm) {
        "Client Attestation POP signer algorithm mismatch: expected ${popAlgorithm.name}, got ${popSignerAlgorithm.name}"
    }
}

sealed class AuthorizationPolicyValidationError(cause: Throwable) : Throwable(cause) {

    class MissingIssuerInfo :
        AuthorizationPolicyValidationError(IllegalArgumentException("Missing issuer info"))

    class MissingRegistrationCertificate :
        AuthorizationPolicyValidationError(IllegalArgumentException("Missing issuer registration certificate"))

    class MultipleRegistrationCertificates :
        AuthorizationPolicyValidationError(IllegalArgumentException("Multiple Registration Certificates provided while only one expected"))

    class MissingAccessCertificate :
        AuthorizationPolicyValidationError(IllegalArgumentException("Missing access certificate"))

    class AuthorizationPolicyNotMet(val violation: RegistrationCertificatePolicy.PolicyViolation) :
        AuthorizationPolicyValidationError(IllegalArgumentException("Authorization policy not met"))

    class MalformedRegistrationCertificate(msg: String) :
        AuthorizationPolicyValidationError(IllegalArgumentException(msg)) {
            init {
                require(msg.isNotEmpty()) { "Cause cannot be empty" }
            }
        }
}
