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

import java.io.Serializable
import kotlin.time.Duration

sealed class EudiReusePolicyType(val jsonValue: String) {
    data object OnceOnly : EudiReusePolicyType("once_only")
    data object LimitedTime : EudiReusePolicyType("limited_time")
    data object RotatingBatch : EudiReusePolicyType("rotating-batch")
    data object PerRelyingParty : EudiReusePolicyType("per-relying-party")

    companion object {
        fun fromJsonValue(value: String): EudiReusePolicyType =
            entries.firstOrNull { it.jsonValue == value }
                ?: throw IllegalArgumentException("Unsupported credential reuse method: $value")

        val entries: List<EudiReusePolicyType> by lazy {
            listOf(
                OnceOnly,
                LimitedTime,
                RotatingBatch,
                PerRelyingParty,
            )
        }
    }
}

/**
 * A single ARF Annex II option in the reuse policy.
 */
sealed interface EudiReusePolicy {

    val batchSize: Int?
    val reissueTriggerUnused: Int?
    val reissueTriggerLifetimeLeft: Duration?

    /**
     * Checks if the client supports this reuse policy option.
     */
    fun isSupported(supportedReusePolicies: CredentialReusePolicies?): Boolean

    data class OnceOnly(
        override val batchSize: Int,
        override val reissueTriggerUnused: Int,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }

        override fun isSupported(supportedReusePolicies: CredentialReusePolicies?): Boolean =
            supportedReusePolicies?.policyTypes?.contains(EudiReusePolicyType.OnceOnly) ?: false

        override val reissueTriggerLifetimeLeft: Duration? = null
    }

    data class LimitedTime(
        override val reissueTriggerLifetimeLeft: Duration,
    ) : EudiReusePolicy {

        init {
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override fun isSupported(supportedReusePolicies: CredentialReusePolicies?): Boolean =
            supportedReusePolicies?.policyTypes?.contains(EudiReusePolicyType.LimitedTime) ?: false

        override val reissueTriggerUnused: Int? = null
        override val batchSize: Int? = null
    }

    data class RotatingBatch(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Duration,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override val reissueTriggerUnused: Int? = null

        override fun isSupported(supportedReusePolicies: CredentialReusePolicies?): Boolean =
            supportedReusePolicies?.policyTypes?.contains(EudiReusePolicyType.RotatingBatch) ?: false
    }

    data class PerRelyingParty(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Duration,
        override val reissueTriggerUnused: Int,
    ) : EudiReusePolicy {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }

        override fun isSupported(supportedReusePolicies: CredentialReusePolicies?): Boolean =
            supportedReusePolicies?.policyTypes?.contains(EudiReusePolicyType.PerRelyingParty) ?: false
    }

    companion object {
        fun fromDetails(
            details: List<EudiReusePolicyType>,
            batchSize: Int? = null,
            reissueTriggerUnused: Int? = null,
            reissueTriggerLifetimeLeft: Duration? = null,
        ): List<EudiReusePolicy> {
            val normalizedDetails = details.distinct()

            require(normalizedDetails.isNotEmpty()) { "details must not be empty" }
            require(normalizedDetails.size == details.size) {
                "details must not contain duplicate values"
            }
            validateBaseMethodCombination(normalizedDetails)

            return normalizedDetails.map { detail ->
                when (detail) {
                    EudiReusePolicyType.OnceOnly -> OnceOnly(
                        batchSize = requireNotNull(batchSize) {
                            "batch_size is required when details contains once_only, rotating-batch, or per-relying-party"
                        },
                        reissueTriggerUnused = requireNotNull(reissueTriggerUnused) {
                            "reissue_trigger_unused is required when details contains once_only"
                        },
                    )

                    EudiReusePolicyType.LimitedTime -> LimitedTime(
                        reissueTriggerLifetimeLeft = requireNotNull(reissueTriggerLifetimeLeft) {
                            "reissue_trigger_lifetime_left is required when details contains limited_time, " +
                                "rotating-batch, or per-relying-party"
                        },
                    )

                    EudiReusePolicyType.RotatingBatch -> RotatingBatch(
                        batchSize = requireNotNull(batchSize) {
                            "batch_size is required when details contains once_only, rotating-batch, or per-relying-party"
                        },
                        reissueTriggerLifetimeLeft = requireNotNull(reissueTriggerLifetimeLeft) {
                            "reissue_trigger_lifetime_left is required when details contains limited_time, " +
                                "rotating-batch, or per-relying-party"
                        },
                    )

                    EudiReusePolicyType.PerRelyingParty -> PerRelyingParty(
                        batchSize = requireNotNull(batchSize) {
                            "batch_size is required when details contains once_only, " +
                                "rotating-batch, or per-relying-party"
                        },
                        reissueTriggerLifetimeLeft = requireNotNull(reissueTriggerLifetimeLeft) {
                            "reissue_trigger_lifetime_left is required when details contains limited_time, " +
                                "rotating-batch, or per-relying-party"
                        },
                        reissueTriggerUnused = requireNotNull(reissueTriggerUnused) {
                            "reissue_trigger_unused is required when details contains once_only or per-relying-party"
                        },
                    )
                }
            }
        }

        private fun validateBaseMethodCombination(details: List<EudiReusePolicyType>) {
            val hasOnceOnly = EudiReusePolicyType.OnceOnly in details
            val hasLimitedTime = EudiReusePolicyType.LimitedTime in details

            require(hasOnceOnly.xor(hasLimitedTime)) {
                "details must contain exactly one base method: once_only or limited_time"
            }
        }

        private fun validateBatchSize(batchSize: Int) {
            require(batchSize > 1) { "batch_size must be greater than 1" }
        }

        private fun validateReissueTriggerUnused(reissueTriggerUnused: Int, batchSize: Int) {
            require(reissueTriggerUnused >= 0) { "reissue_trigger_unused must be non-negative" }
            require(reissueTriggerUnused < batchSize) { "reissue_trigger_unused must be lower than batch_size" }
        }

        private fun validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft: Duration) {
            require(reissueTriggerLifetimeLeft.isPositive()) { "reissue_trigger_lifetime_left must be greater than 0" }
        }
    }
}

/**
 * Credential reuse policy as it may appear in the credential metadata of a credential configuration.
 *
 */
sealed interface CredentialReusePolicy : Serializable {

    /**
     * No reuse policy is defined.
     */
    data object None : CredentialReusePolicy {
        private fun readResolve(): Any = None
    }

    /**
     * ARF Annex II reuse policy.
     *
     * @param options extra details about the specific reuse policy
     */
    data class EUDI(
        val options: List<EudiReusePolicy>,
    ) : CredentialReusePolicy {

        init {
            require(options.isNotEmpty()) { "options must not be empty for arf_annex_ii policy" }
            validateNoOverlappingDetails(options)
        }

        companion object {

            private fun validateNoOverlappingDetails(options: List<EudiReusePolicy>) {
                if (options.size <= 1) return
                val optionTypes = options.map { it::class }
                require(optionTypes.size == optionTypes.toSet().size) {
                    "When multiple policy options are defined, each option type must be unique"
                }
            }
        }
    }
}
