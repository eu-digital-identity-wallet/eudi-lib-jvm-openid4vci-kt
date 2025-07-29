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
package eu.europa.ec.eudi.openid4vci.examples

import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.measureTime

@DisplayName("PID DEV Issuer Test")
class PidDevIssuerTest {

    @Test
    @Ignore
    fun `Issue PID in mso_mdoc using authorize code flow and JWT proofs`() = runTest {
        repeatBatchIssuanceUsingAuthorizationCodeFlow(
            PidDevIssuer.PID_MsoMdoc_config_id,
            ProofsType.JwtProofsNoKeyAttestation(BatchOption.Specific(2)),
        )
    }

    @Test
    @Ignore
    fun `Issue PID in sd-jwt vc using authorize code flow and JWT proofs`() = runTest {
        repeatBatchIssuanceUsingAuthorizationCodeFlow(
            PidDevIssuer.PID_SdJwtVC_config_id,
            ProofsType.JwtProofsNoKeyAttestation(BatchOption.Specific(2)),
        )
    }

    @Test
    @Ignore
    fun `Issue mDL in mso_mdoc using authorize code flow and JWT proofs`() = runTest {
        repeatBatchIssuanceUsingAuthorizationCodeFlow(
            PidDevIssuer.MDL_config_id,
            ProofsType.JwtProofsNoKeyAttestation(BatchOption.Specific(2)),
        )
    }

    @Test
    @Ignore
    fun `Issue EHIC in sd-jwt vc jws json flattened using authorize code flow and JWT proofs`() = runTest {
        repeatBatchIssuanceUsingAuthorizationCodeFlow(
            PidDevIssuer.EHIC_JwsJson_config_id,
            ProofsType.JwtProofWithKeyAttestation(BatchOption.Specific(2)),
        )
    }

    @Test
    @Ignore
    fun `Issue EHIC in sd-jwt vc compact using authorize code flow and JWT proofs`() = runTest {
        repeatBatchIssuanceUsingAuthorizationCodeFlow(
            PidDevIssuer.EHIC_Compact_config_id,
            ProofsType.JwtProofWithKeyAttestation(BatchOption.Specific(2)),
        )
    }
}

private suspend fun repeatBatchIssuanceUsingAuthorizationCodeFlow(
    credentialConfigurationIdentifier: CredentialConfigurationIdentifier,
    proofsType: ProofsType,
    enableHttpLogging: Boolean = false,
    repetitions: UInt = 1u,
    delayBetweenRepetitions: Duration = 0.seconds,
) {
    require(repetitions > 0u) { "repetitions must be greater than 0" }
    createHttpClient(enableHttpLogging).use { httpClient ->
        repeat(repetitions.toInt()) {
            val duration = measureTime {
                PidDevIssuer.testIssuanceWithAuthorizationCodeFlow(
                    credentialConfigurationIdentifier,
                    proofsType = proofsType,
                    httpClient = httpClient,
                )
            }
            println("It took ${duration.inWholeMilliseconds} milliseconds to issue ${credentialConfigurationIdentifier.value}")
            delay(delayBetweenRepetitions)
        }
    }
}
