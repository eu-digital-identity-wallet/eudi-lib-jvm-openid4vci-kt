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

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

internal class CredentialReusePolicyTest {

    @Test
    fun `once_only option is valid with batch_size and reissue_trigger_unused`() {
        val option = ReusePolicyOption(
            details = listOf(ReuseMethod.ONCE_ONLY),
            batchSize = 10,
            reissueTriggerUnused = 4,
        )
        assertEquals(10, option.batchSize)
        assertEquals(4, option.reissueTriggerUnused)
        assertNull(option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `limited_time option is valid with reissue_trigger_lifetime_left`() {
        val option = ReusePolicyOption(
            details = listOf(ReuseMethod.LIMITED_TIME),
            reissueTriggerLifetimeLeft = 885433,
        )
        assertNull(option.batchSize)
        assertNull(option.reissueTriggerUnused)
        assertEquals(885433, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `limited_time with rotating-batch and per-relying-party is valid`() {
        val option = ReusePolicyOption(
            details = listOf(ReuseMethod.LIMITED_TIME, ReuseMethod.ROTATING_BATCH, ReuseMethod.PER_RELYING_PARTY),
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433,
        )
        assertEquals(5, option.batchSize)
        assertEquals(655433, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `once_only with rotating-batch is valid`() {
        val option = ReusePolicyOption(
            details = listOf(ReuseMethod.ONCE_ONLY, ReuseMethod.ROTATING_BATCH),
            batchSize = 20,
            reissueTriggerUnused = 5,
            reissueTriggerLifetimeLeft = 100000,
        )
        assertEquals(20, option.batchSize)
        assertEquals(5, option.reissueTriggerUnused)
        assertEquals(100000, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `fails when details is empty`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(details = emptyList())
        }
    }

    @Test
    fun `fails when details has neither once_only nor limited_time`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.ROTATING_BATCH),
                batchSize = 10,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fails when details has both once_only and limited_time`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.ONCE_ONLY, ReuseMethod.LIMITED_TIME),
                batchSize = 10,
                reissueTriggerUnused = 2,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fails when once_only is missing batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.ONCE_ONLY),
                reissueTriggerUnused = 2,
            )
        }
    }

    @Test
    fun `fails when once_only is missing reissue_trigger_unused`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.ONCE_ONLY),
                batchSize = 10,
            )
        }
    }

    @Test
    fun `fails when reissue_trigger_unused is not lower than batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.ONCE_ONLY),
                batchSize = 10,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `fails when limited_time is missing reissue_trigger_lifetime_left`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.LIMITED_TIME),
            )
        }
    }

    @Test
    fun `fails when rotating-batch is missing batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            ReusePolicyOption(
                details = listOf(ReuseMethod.LIMITED_TIME, ReuseMethod.ROTATING_BATCH),
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `CredentialReusePolicy with arf_annex_ii requires non-empty options`() {
        assertFailsWith<IllegalArgumentException> {
            CredentialReusePolicy(id = "arf_annex_ii", options = emptyList())
        }
    }

    @Test
    fun `CredentialReusePolicy with arf_annex_ii requires options present`() {
        assertFailsWith<IllegalArgumentException> {
            CredentialReusePolicy(id = "arf_annex_ii", options = null)
        }
    }

    @Test
    fun `CredentialReusePolicy with non-arf id allows no options`() {
        val policy = CredentialReusePolicy(id = "custom_policy")
        assertEquals("custom_policy", policy.id)
        assertNull(policy.options)
    }

    @Test
    fun `CredentialReusePolicy fails with overlapping details across options`() {
        assertFailsWith<IllegalArgumentException> {
            CredentialReusePolicy(
                id = "arf_annex_ii",
                options = listOf(
                    ReusePolicyOption(
                        details = listOf(ReuseMethod.ONCE_ONLY, ReuseMethod.ROTATING_BATCH),
                        batchSize = 10,
                        reissueTriggerUnused = 4,
                        reissueTriggerLifetimeLeft = 100,
                    ),
                    ReusePolicyOption(
                        details = listOf(ReuseMethod.ROTATING_BATCH, ReuseMethod.ONCE_ONLY),
                        batchSize = 20,
                        reissueTriggerUnused = 5,
                        reissueTriggerLifetimeLeft = 200,
                    ),
                ),
            )
        }
    }

    @Test
    fun `CredentialReusePolicy with multiple non-overlapping options is valid`() {
        val policy = CredentialReusePolicy(
            id = "arf_annex_ii",
            options = listOf(
                ReusePolicyOption(
                    details = listOf(ReuseMethod.ONCE_ONLY),
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
                ReusePolicyOption(
                    details = listOf(ReuseMethod.ONCE_ONLY, ReuseMethod.ROTATING_BATCH),
                    batchSize = 20,
                    reissueTriggerUnused = 5,
                    reissueTriggerLifetimeLeft = 100,
                ),
            ),
        )
        assertEquals(2, policy.options!!.size)
    }

    @Test
    fun `effectiveBatchSize returns first batch_size from supported options`() {
        val policy = CredentialReusePolicy(
            id = "arf_annex_ii",
            options = listOf(
                ReusePolicyOption(
                    details = listOf(ReuseMethod.LIMITED_TIME, ReuseMethod.ROTATING_BATCH),
                    batchSize = 5,
                    reissueTriggerLifetimeLeft = 885433,
                ),
                ReusePolicyOption(
                    details = listOf(ReuseMethod.ONCE_ONLY),
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
            ),
        )
        // If ROTATING_BATCH is not supported, it should pick the second one
        assertEquals(10, policy.effectiveBatchSize(setOf(ReuseMethod.ONCE_ONLY)))

        // If ROTATING_BATCH is supported, it should pick the first one
        assertEquals(5, policy.effectiveBatchSize(setOf(ReuseMethod.LIMITED_TIME, ReuseMethod.ROTATING_BATCH)))
    }

    @Test
    fun `effectiveBatchSize returns null when no batch_size present in supported options`() {
        val policy = CredentialReusePolicy(
            id = "arf_annex_ii",
            options = listOf(
                ReusePolicyOption(
                    details = listOf(ReuseMethod.LIMITED_TIME),
                    reissueTriggerLifetimeLeft = 885433,
                ),
                ReusePolicyOption(
                    details = listOf(ReuseMethod.ONCE_ONLY),
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
            ),
        )
        // Only LIMITED_TIME is supported, which doesn't have batch_size
        assertNull(policy.effectiveBatchSize(setOf(ReuseMethod.LIMITED_TIME)))
    }

    @Test
    fun `ArfReuseMethod jsonValue round-trip`() {
        for (method in ReuseMethod.entries) {
            assertEquals(method, ReuseMethod.fromJsonValue(method.jsonValue))
        }
    }

    @Test
    fun `ArfReuseMethod fromJsonValue returns null for unknown`() {
        assertNull(ReuseMethod.fromJsonValue("unknown_method"))
    }
}
