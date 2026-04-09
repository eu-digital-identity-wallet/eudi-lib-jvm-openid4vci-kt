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

/**
 * Functional interface to define a sign operation.
 * This interface is typically implemented to enable signing of input data
 * and returning the signed result.
 */
fun interface SignFunction {

    suspend fun sign(input: ByteArray): ByteArray

    companion object
}

/**
 * Represents a data class encapsulating a signing operation configuration.
 *
 * @param PUB The type of the public material used in the signing process.
 * @property function The signing operation to be executed, represented by the [SignFunction] functional interface.
 * @property publicMaterial The public material associated with the signing operation.
 */
data class SignOperation<out PUB>(
    val function: SignFunction,
    val publicMaterial: PUB,
)

/**
 * Represents a generic Signer interface that manages signing operations.
 *
 * @param PUB The type of the public material used in the signing process.
 */
interface Signer<out PUB> {

    /**
     * The algorithm that will be used for signing
     */
    val javaAlgorithm: String

    /**
     * Performs the acquisition operation and returns a signing operation configuration object.
     *
     * @return A [SignOperation] instance containing the configuration of the signing operation,
     *         including the signing algorithm, the operation to be executed, and the public material.
     */
    suspend fun acquire(): SignOperation<PUB>

    /**
     * Releases the resources associated with the provided signing operation.
     * This method is used to clean up or finalize operations when a signing process
     * is no longer needed.
     *
     * @param signOperation The signing operation to be released. It can be null, in which case
     *               no action will be performed.
     */
    suspend fun release(signOperation: SignOperation<@UnsafeVariance PUB>?)

    companion object
}
