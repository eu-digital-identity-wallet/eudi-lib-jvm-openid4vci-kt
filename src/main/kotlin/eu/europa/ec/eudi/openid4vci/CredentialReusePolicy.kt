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
        fun fromJsonValue(value: String): ArfAnnex2ReuseMethod? = entries.firstOrNull { it.jsonValue == value }
    }
}

/**
 * A single option in the reuse policy.
 *
 * @param details the reuse methods for this option; must contain either [ArfAnnex2ReuseMethod.ONCE_ONLY] or [ArfAnnex2ReuseMethod.LIMITED_TIME] (but not both)
 * @param batchSize the size of the batch during issuance (required if details contains once_only, rotating-batch, or per-relying-party)
 * @param reissueTriggerUnused lower limit of unused attestations that triggers re-issuance (required if details contains once_only)
 * @param reissueTriggerLifetimeLeft seconds before expiration that triggers re-issuance (required if details contains limited_time, rotating-batch, or per-relying-party)
 */
data class ArfAnnex2ReusePolicyOption(
    val details: List<ArfAnnex2ReuseMethod>,
    val batchSize: Int? = null,
    val reissueTriggerUnused: Int? = null,
    val reissueTriggerLifetimeLeft: Long? = null,
) : Serializable {

    init {
        val hasOnceOnly = ArfAnnex2ReuseMethod.ONCE_ONLY in details
        val hasLimitedTime = ArfAnnex2ReuseMethod.LIMITED_TIME in details
        val hasRotatingBatch = ArfAnnex2ReuseMethod.ROTATING_BATCH in details
        val hasPerRelyingParty = ArfAnnex2ReuseMethod.PER_RELYING_PARTY in details

        require(details.isNotEmpty()) { "details must not be empty" }
        require(hasOnceOnly || hasLimitedTime) {
            "details must contain either once_only or limited_time"
        }
        require(!(hasOnceOnly && hasLimitedTime)) {
            "details must not contain both once_only and limited_time"
        }

        val requiresBatchSize = hasOnceOnly || hasRotatingBatch || hasPerRelyingParty
        if (requiresBatchSize) {
            requireNotNull(batchSize) { "batch_size is required when details contains once_only, rotating-batch, or per-relying-party" }
            require(batchSize > 0) { "batch_size must be greater than 0" }
        }

        if (hasOnceOnly) {
            requireNotNull(reissueTriggerUnused) { "reissue_trigger_unused is required when details contains once_only" }
            require(reissueTriggerUnused >= 0) { "reissue_trigger_unused must be non-negative" }
            if (batchSize != null) {
                require(reissueTriggerUnused < batchSize) { "reissue_trigger_unused must be lower than batch_size" }
            }
        }

        val requiresLifetimeLeft = hasLimitedTime || hasRotatingBatch || hasPerRelyingParty
        if (requiresLifetimeLeft) {
            requireNotNull(reissueTriggerLifetimeLeft) {
                "reissue_trigger_lifetime_left is required when details contains limited_time, rotating-batch, or per-relying-party"
            }
            require(reissueTriggerLifetimeLeft > 0) { "reissue_trigger_lifetime_left must be greater than 0" }
        }
    }

    /**
     * Checks if this reuse policy option is supported by the client.
     */
    fun isSupported(supportedReuseMethods: Set<ArfAnnex2ReuseMethod>): Boolean =
        details.all { it in supportedReuseMethods }
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
                val normalizedDetailsCombinations = options.map { option ->
                    option.details
                        .sortedBy(ArfAnnex2ReuseMethod::name)
                        .joinToString(separator = "|") { it.name }
                }
                require(normalizedDetailsCombinations.size == normalizedDetailsCombinations.toSet().size) {
                    "When multiple policy options are defined, the values in the respective details attribute must be unique"
                }
            }
        }
    }
}
