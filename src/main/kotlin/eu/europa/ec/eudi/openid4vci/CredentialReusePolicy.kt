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

enum class ArfAnnex2ReuseMethod {
    ONCE_ONLY,
    LIMITED_TIME,
    ROTATING_BATCH,
    PER_RELYING_PARTY,
    ;

    val jsonValue: String
        get() = when (this) {
            ONCE_ONLY -> "once_only"
            LIMITED_TIME -> "limited_time"
            ROTATING_BATCH -> "rotating-batch"
            PER_RELYING_PARTY -> "per-relying-party"
        }

    companion object {
        fun fromJsonValue(value: String): ArfAnnex2ReuseMethod =
            entries.firstOrNull { it.jsonValue == value }
                ?: throw IllegalArgumentException("Unsupported arf_annex_ii reuse method: $value")
    }
}

/**
 * A single option in the reuse policy.
 */
sealed interface ReusePolicyOption : Serializable

/**
 * A single ARF Annex II option in the reuse policy.
 */
sealed interface ArfAnnex2ReusePolicyOption : ReusePolicyOption {

    val batchSize: Int?
    val reissueTriggerUnused: Int?
    val reissueTriggerLifetimeLeft: Long?

    /**
     * Checks if the client supports this reuse policy option.
     */
    fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean

    data class OnceOnly(
        override val batchSize: Int,
        override val reissueTriggerUnused: Int,
    ) : ArfAnnex2ReusePolicyOption {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }

        override fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean =
            supportedReuseMethods.contains(ArfAnnex2ReuseMethod.ONCE_ONLY)

        override val reissueTriggerLifetimeLeft: Long? = null
    }

    data class LimitedTime(
        override val reissueTriggerLifetimeLeft: Long,
    ) : ArfAnnex2ReusePolicyOption {

        init {
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean =
            supportedReuseMethods.contains(ArfAnnex2ReuseMethod.LIMITED_TIME)

        override val reissueTriggerUnused: Int? = null
        override val batchSize: Int? = null
    }

    data class RotatingBatch(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Long,
    ) : ArfAnnex2ReusePolicyOption {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
        }

        override val reissueTriggerUnused: Int? = null

        override fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean =
            supportedReuseMethods.contains(ArfAnnex2ReuseMethod.ROTATING_BATCH)
    }

    data class PerRelyingParty(
        override val batchSize: Int,
        override val reissueTriggerLifetimeLeft: Long,
        override val reissueTriggerUnused: Int,
    ) : ArfAnnex2ReusePolicyOption {

        init {
            validateBatchSize(batchSize)
            validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft)
            validateReissueTriggerUnused(reissueTriggerUnused, batchSize)
        }

        override fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean =
            supportedReuseMethods.contains(ArfAnnex2ReuseMethod.PER_RELYING_PARTY)
    }

    companion object {
        fun fromDetails(
            details: List<ArfAnnex2ReuseMethod>,
            batchSize: Int? = null,
            reissueTriggerUnused: Int? = null,
            reissueTriggerLifetimeLeft: Long? = null,
        ): List<ArfAnnex2ReusePolicyOption> {
            val normalizedDetails = details.distinct()

            require(normalizedDetails.isNotEmpty()) { "details must not be empty" }
            require(normalizedDetails.size == details.size) {
                "details must not contain duplicate values"
            }
            validateBaseMethodCombination(normalizedDetails)

            return normalizedDetails.map { detail ->
                when (detail) {
                    ArfAnnex2ReuseMethod.ONCE_ONLY -> OnceOnly(
                        batchSize = requireNotNull(batchSize) {
                            "batch_size is required when details contains once_only, rotating-batch, or per-relying-party"
                        },
                        reissueTriggerUnused = requireNotNull(reissueTriggerUnused) {
                            "reissue_trigger_unused is required when details contains once_only"
                        },
                    )

                    ArfAnnex2ReuseMethod.LIMITED_TIME -> LimitedTime(
                        reissueTriggerLifetimeLeft = requireNotNull(reissueTriggerLifetimeLeft) {
                            "reissue_trigger_lifetime_left is required when details contains limited_time, " +
                                "rotating-batch, or per-relying-party"
                        },
                    )

                    ArfAnnex2ReuseMethod.ROTATING_BATCH -> RotatingBatch(
                        batchSize = requireNotNull(batchSize) {
                            "batch_size is required when details contains once_only, rotating-batch, or per-relying-party"
                        },
                        reissueTriggerLifetimeLeft = requireNotNull(reissueTriggerLifetimeLeft) {
                            "reissue_trigger_lifetime_left is required when details contains limited_time, " +
                                "rotating-batch, or per-relying-party"
                        },
                    )

                    ArfAnnex2ReuseMethod.PER_RELYING_PARTY -> PerRelyingParty(
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

        private fun validateBaseMethodCombination(details: List<ArfAnnex2ReuseMethod>) {
            val hasOnceOnly = ArfAnnex2ReuseMethod.ONCE_ONLY in details
            val hasLimitedTime = ArfAnnex2ReuseMethod.LIMITED_TIME in details

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

        private fun validateReissueTriggerLifetimeLeft(reissueTriggerLifetimeLeft: Long) {
            require(reissueTriggerLifetimeLeft > 0) { "reissue_trigger_lifetime_left must be greater than 0" }
        }
    }
}

/**
 * Sealed hierarchy representing the reuse policies supported by the wallet.
 */
sealed interface SupportedReusePolicy : Serializable {

    /**
     * The wallet supports ARF Annex II reuse policy with specific reuse methods.
     *
     * @param supportedReuseMethods the reuse methods supported by the wallet
     */
    data class ArfAnnex2ReusePolicy(
        val supportedReuseMethods: Set<ArfAnnex2ReuseMethod>,
    ) : SupportedReusePolicy {
        init {
            require(supportedReuseMethods.isNotEmpty()) { "supportedReuseMethods must not be empty" }
        }
    }
}

/**
 * Credential reuse policy as it may appear in the credential metadata of a credential configuration.
 *
 */
sealed interface CredentialReusePolicy : Serializable {

    /**
     * Returns the effective batch size for this reuse policy, if the policy dictates batch issuance.
     */
    fun effectiveBatchSize(supportedReusePolicies: Set<SupportedReusePolicy>): Int?

    /**
     * No reuse policy is defined.
     */
    data object None : CredentialReusePolicy {
        private fun readResolve(): Any = None
        override fun effectiveBatchSize(supportedReusePolicies: Set<SupportedReusePolicy>): Int? = null
    }

    /**
     * ARF Annex II reuse policy.
     *
     * @param options extra details about the specific reuse policy
     */
    data class ArfAnnex2ReusePolicy(
        val options: List<ArfAnnex2ReusePolicyOption>,
    ) : CredentialReusePolicy {

        init {
            require(options.isNotEmpty()) { "options must not be empty for arf_annex_ii policy" }
            validateNoOverlappingDetails(options)
        }

        /**
         * For ARF Annex II, returns the batch_size from the first option that is supported and has it.
         */
        override fun effectiveBatchSize(supportedReusePolicies: Set<SupportedReusePolicy>): Int? {
            val supportedMethods = supportedReusePolicies
                .filterIsInstance<SupportedReusePolicy.ArfAnnex2ReusePolicy>()
                .flatMap { it.supportedReuseMethods }
                .toSet()
            return options
                .filter { it.isSupported(supportedMethods) }
                .firstNotNullOfOrNull { it.batchSize }
        }

        companion object {
            const val ID = "arf_annex_ii"

            private fun validateNoOverlappingDetails(options: List<ArfAnnex2ReusePolicyOption>) {
                if (options.size <= 1) return
                val optionTypes = options.map { it::class }
                require(optionTypes.size == optionTypes.toSet().size) {
                    "When multiple policy options are defined, each ArfAnnex2ReusePolicyOption type must be unique"
                }
            }
        }
    }
}
