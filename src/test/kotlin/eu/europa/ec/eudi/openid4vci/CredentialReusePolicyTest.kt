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

import kotlin.test.*

internal class CredentialReusePolicyTest {

    @Test
    fun `once_only option is valid with batch_size and reissue_trigger_unused`() {
        val option = EudiReusePolicy.OnceOnly(
            batchSize = 10,
            reissueTriggerUnused = 4,
        )
        assertEquals(10, option.batchSize)
        assertEquals(4, option.reissueTriggerUnused)
        assertNull(option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `limited_time option is valid with reissue_trigger_lifetime_left`() {
        val option = EudiReusePolicy.LimitedTime(
            reissueTriggerLifetimeLeft = 885433,
        )
        assertNull(option.batchSize)
        assertNull(option.reissueTriggerUnused)
        assertEquals(885433, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `limited_time with rotating-batch and per-relying-party is valid`() {
        val option = EudiReusePolicy.PerRelyingParty(
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433,
            reissueTriggerUnused = 3,
        )
        assertIs<EudiReusePolicy.PerRelyingParty>(option)
        assertEquals(5, option.batchSize)
        assertEquals(655433, option.reissueTriggerLifetimeLeft)
        assertEquals(3, option.reissueTriggerUnused)
    }

    @Test
    fun `once_only with rotating-batch is valid`() {
        val option = EudiReusePolicy.RotatingBatch(
            batchSize = 20,
            reissueTriggerLifetimeLeft = 100000,
        )
        assertIs<EudiReusePolicy.RotatingBatch>(option)
        assertEquals(20, option.batchSize)
        assertEquals(100000, option.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `fails when details is empty`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(details = emptyList())
        }
    }

    @Test
    fun `fails when rotating-batch is used without a base detail`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.ROTATING_BATCH),
                batchSize = 10,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fails when per-relying-party is used without a base detail`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.PER_RELYING_PARTY),
                batchSize = 10,
                reissueTriggerUnused = 2,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fails when details contains both once_only and limited_time`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.ONCE_ONLY, EudiReusePolicyType.LIMITED_TIME),
                batchSize = 10,
                reissueTriggerUnused = 2,
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fails when once_only is missing batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.ONCE_ONLY),
                reissueTriggerUnused = 2,
            )
        }
    }

    @Test
    fun `fails when once_only is missing reissue_trigger_unused`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.ONCE_ONLY),
                batchSize = 10,
            )
        }
    }

    @Test
    fun `fails when reissue_trigger_unused is not lower than batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.OnceOnly(
                batchSize = 10,
                reissueTriggerUnused = 10,
            )
        }
    }

    @Test
    fun `fails when limited_time is missing reissue_trigger_lifetime_left`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.LIMITED_TIME),
            )
        }
    }

    @Test
    fun `fails when rotating-batch is missing batch_size`() {
        assertFailsWith<IllegalArgumentException> {
            EudiReusePolicy.fromDetails(
                details = listOf(EudiReusePolicyType.LIMITED_TIME, EudiReusePolicyType.ROTATING_BATCH),
                reissueTriggerLifetimeLeft = 100,
            )
        }
    }

    @Test
    fun `fromDetails returns one option per detail entry`() {
        val options = EudiReusePolicy.fromDetails(
            details = listOf(
                EudiReusePolicyType.LIMITED_TIME,
                EudiReusePolicyType.ROTATING_BATCH,
                EudiReusePolicyType.PER_RELYING_PARTY,
            ),
            batchSize = 5,
            reissueTriggerLifetimeLeft = 655433,
            reissueTriggerUnused = 3,
        )

        assertEquals(3, options.size)
        assertIs<EudiReusePolicy.LimitedTime>(options[0])
        val rotatingBatch = assertIs<EudiReusePolicy.RotatingBatch>(options[1])
        assertEquals(5, rotatingBatch.batchSize)
        assertEquals(655433, rotatingBatch.reissueTriggerLifetimeLeft)
        assertIs<EudiReusePolicy.PerRelyingParty>(options[2])
    }

    @Test
    fun `fromDetails returns once_only and per_relying_party options for combined details`() {
        val options = EudiReusePolicy.fromDetails(
            details = listOf(
                EudiReusePolicyType.ONCE_ONLY,
                EudiReusePolicyType.PER_RELYING_PARTY,
            ),
            batchSize = 10,
            reissueTriggerUnused = 3,
            reissueTriggerLifetimeLeft = 200,
        )

        assertEquals(2, options.size)
        assertIs<EudiReusePolicy.OnceOnly>(options[0])
        val perRelyingParty = assertIs<EudiReusePolicy.PerRelyingParty>(options[1])
        assertEquals(10, perRelyingParty.batchSize)
        assertEquals(3, perRelyingParty.reissueTriggerUnused)
        assertEquals(200, perRelyingParty.reissueTriggerLifetimeLeft)
    }

    @Test
    fun `ArfAnnex2ReusePolicy requires non-empty options`() {
        assertFailsWith<IllegalArgumentException> {
            CredentialReusePolicy.EUDI(options = emptyList())
        }
    }

    @Test
    fun `CredentialReusePolicy None has no effective batch size`() {
        val policy = CredentialReusePolicy.None
        assertNull(policy.effectiveBatchSize(EudiReusePolicyType.entries.toSet()))
    }

    @Test
    fun `ArfAnnex2ReusePolicy fails with overlapping details across options`() {
        assertFailsWith<IllegalArgumentException> {
            CredentialReusePolicy.EUDI(
                options = listOf(
                    EudiReusePolicy.RotatingBatch(
                        batchSize = 10,
                        reissueTriggerLifetimeLeft = 100,
                    ),
                    EudiReusePolicy.RotatingBatch(
                        batchSize = 20,
                        reissueTriggerLifetimeLeft = 200,
                    ),
                ),
            )
        }
    }

    @Test
    fun `ArfAnnex2ReusePolicy with multiple non-overlapping options is valid`() {
        val policy = CredentialReusePolicy.EUDI(
            options = listOf(
                EudiReusePolicy.OnceOnly(
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
                EudiReusePolicy.RotatingBatch(
                    batchSize = 20,
                    reissueTriggerLifetimeLeft = 100,
                ),
            ),
        )
        assertEquals(2, policy.options.size)
    }

    @Test
    fun `effectiveBatchSize returns first batch_size from supported options`() {
        val policy = CredentialReusePolicy.EUDI(
            options = listOf(
                EudiReusePolicy.RotatingBatch(
                    batchSize = 5,
                    reissueTriggerLifetimeLeft = 885433,
                ),
                EudiReusePolicy.OnceOnly(
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
            ),
        )
        // If ROTATING_BATCH is not supported, it should pick the second one
        assertEquals(10, policy.effectiveBatchSize(setOf(EudiReusePolicyType.ONCE_ONLY)))

        // If ROTATING_BATCH is supported, it should pick the first one
        assertEquals(
            5,
            policy.effectiveBatchSize(
                setOf(EudiReusePolicyType.LIMITED_TIME, EudiReusePolicyType.ROTATING_BATCH),
            ),
        )
    }

    @Test
    fun `effectiveBatchSize returns null when no batch_size present in supported options`() {
        val policy = CredentialReusePolicy.EUDI(
            options = listOf(
                EudiReusePolicy.LimitedTime(
                    reissueTriggerLifetimeLeft = 885433,
                ),
                EudiReusePolicy.OnceOnly(
                    batchSize = 10,
                    reissueTriggerUnused = 4,
                ),
            ),
        )
        // Only LIMITED_TIME is supported, which doesn't have batch_size
        assertNull(policy.effectiveBatchSize(setOf(EudiReusePolicyType.LIMITED_TIME)))
    }

    @Test
    fun `ArfReuseMethod jsonValue round-trip`() {
        for (method in EudiReusePolicyType.entries) {
            assertEquals(method, EudiReusePolicyType.fromJsonValue(method.jsonValue))
        }
    }

    @Test
    fun `ArfReuseMethod fromJsonValue fails for unknown`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            EudiReusePolicyType.fromJsonValue("unknown_method")
        }

        assertTrue(exception.message?.contains("unknown_method") == true)
    }
}
