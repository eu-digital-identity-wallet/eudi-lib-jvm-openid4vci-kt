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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GetAuthorizationCodeURLTest {

    @Test
    fun `Fails when not an https URL`() {
        assertFailsWith<IllegalArgumentException>(
            message = "Must be an https url",
            block = {
                AuthorizationUrl("http://issuer")
            },
        )
    }

    @Test
    fun `Fails no client_id query param`() {
        var exception = assertFailsWith<IllegalArgumentException>(
            message = "URL must contain client_id query parameter",
            block = {
                AuthorizationUrl("https://issuer")
            },
        )
        assertTrue(exception.message.equals("URL must contain query parameter"))

        exception = assertFailsWith<IllegalArgumentException>(
            message = "URL must contain client_id query parameter",
            block = {
                AuthorizationUrl("https://issuer?param=client_id")
            },
        )
        assertEquals("URL must contain client_id query parameter", exception.message)
    }

    @Test
    fun `Fails no request_uri query param`() {
        var exception = assertFailsWith<IllegalArgumentException>(
            message = "URL must contain request_uri query parameter",
            block = { AuthorizationUrl("https://issuer?client_id=wallet_client_id") },
        )
        assertEquals("URL must contain request_uri query parameter", exception.message)

        exception = assertFailsWith<IllegalArgumentException>(
            message = "URL must contain request_uri query parameter",
            block = {
                AuthorizationUrl("https://issuer?client_id=wallet_client_id")
            },
        )
        assertEquals("URL must contain request_uri query parameter", exception.message)
    }

    @Test
    fun `Succeeds when is https and client_id and request_uri query param are provided`() {
        AuthorizationUrl("https://issuer?client_id=wallet_client_id&request_uri=uri%3Arequest_uri%3AYUIO123")
    }
}
