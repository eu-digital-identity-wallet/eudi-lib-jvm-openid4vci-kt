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

import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.DisplayName
import kotlin.test.Ignore
import kotlin.test.Test

@DisplayName("PID DEV Issuer Test")
class PidDevIssuerTest {

    @Test @Ignore
    fun `Issue PID in mso_mdoc using authorize code flow and JWT proofs`() = runTest {
        PidDevIssuer.testIssuanceWithAuthorizationCodeFlow(
            PidDevIssuer.PID_MsoMdoc_config_id,
            enableHttpLogging = false,
            batchOption = BatchOption.Specific(2),
        )
    }

    @Test @Ignore
    fun `Issue PID in sd-jwt-vc using authorize code flow and JWT proofs`() = runTest {
        PidDevIssuer.testIssuanceWithAuthorizationCodeFlow(
            PidDevIssuer.PID_SdJwtVC_config_id,
            enableHttpLogging = false,
            batchOption = BatchOption.Specific(2),
        )
    }

    @Test @Ignore
    fun `Issue mDL in mso_mdoc using authorize code flow and JWT proofs`() = runTest {
        PidDevIssuer.testIssuanceWithAuthorizationCodeFlow(
            PidDevIssuer.MDL_config_id,
            enableHttpLogging = false,
            batchOption = BatchOption.Specific(2),
        )
    }
}
