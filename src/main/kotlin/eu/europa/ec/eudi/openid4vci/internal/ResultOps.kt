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
package eu.europa.ec.eudi.openid4vci.internal

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

//
// Helper methods
//
internal fun <T> T.success(): Result<T> = Result.success(this)
internal fun <T> Result<T>.mapError(map: (Throwable) -> Throwable): Result<T> =
    fold(onSuccess = { it.success() }, onFailure = { Result.failure(map(it)) })

internal fun <T> Result<T>.ensureSuccess(ex: (Throwable) -> Throwable): T =
    fold(
        onSuccess = { it },
        onFailure = { t -> throw ex(t) },
    )

@OptIn(ExperimentalContracts::class)
internal inline fun ensure(value: Boolean, ex: () -> Throwable) {
    contract {
        returns() implies value
    }
    if (!value) throw ex()
}

@OptIn(ExperimentalContracts::class)
internal inline fun <T : Any> ensureNotNull(value: T?, ex: () -> Throwable): T {
    contract {
        returns() implies (value != null)
    }
    if (value == null) throw ex()
    return value
}
