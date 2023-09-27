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

import org.junit.jupiter.api.Assertions
import java.net.URI
import kotlin.test.Test

internal class CredentialIssuerIdTest {

    @Test
    internal fun `Fails with non https URL`() {
        val maybeId = CredentialIssuerId("ftp://issuer")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Fails with https URL with fragment`() {
        val maybeId = CredentialIssuerId("ftp://issuer#fragment")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Fails with https URL with query parameters`() {
        val maybeId = CredentialIssuerId("ftp://issuer?param1=true&param2=true")
        Assertions.assertTrue(maybeId.isFailure, "Parsing CredentialIssuerId should have failed")
    }

    @Test
    internal fun `Parsing succeeds`() {
        val value = URI("https://issuer")
        val maybeId = CredentialIssuerId(value.toString())
        Assertions.assertTrue(maybeId.isSuccess, "Parsing CredentialIssuerId should have succeeded")
        Assertions.assertEquals(value, maybeId.getOrThrow().value.value)
    }
}
