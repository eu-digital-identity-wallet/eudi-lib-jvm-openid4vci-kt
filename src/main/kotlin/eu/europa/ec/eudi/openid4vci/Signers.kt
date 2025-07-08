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
 * Represents a batch of signing operations that can be executed together.
 *
 * @param PUB The type of the public material used in the signing operations.
 * @property operations A list of [SignOperation] instances specifying the individual signing operations
 * to be performed in the batch.
 */
data class BatchSignOperation<out PUB>(
    val operations: List<SignOperation<PUB>>,
)

/**
 * Represents a generic Signer interface that manages signing operations.
 *
 * @param PUB The type of the public material used in the signing process.
 */
interface Signer<out PUB> {

    val javaAlgorithm: String

    /**
     * Performs the authentication operation and returns a signing operation configuration object.
     *
     * @return A [SignOperation] instance containing the configuration of the signing operation,
     *         including the signing algorithm, the operation to be executed, and the public material.
     */
    suspend fun authenticate(): SignOperation<PUB>

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

/**
 * Defines an interface for batch signing operations.
 *
 * This interface is intended for managing batches of signing operations, allowing
 * for the authentication of a batch and the ability to release resources associated
 * with a batch. Implementations should provide the logic for authenticating signing
 * operations and releasing resources appropriately.
 *
 * @param PUB The type of the public material used in the signing operations.
 */
interface BatchSigner<out PUB> {

    val javaAlgorithm: String

    /**
     * Authenticates a batch signing operation.
     *
     * The method initiates the process of authenticating signing operations that are
     * structured as a batch. Authentication ensures that the signing operations
     * meet the required security and validity conditions.
     *
     * @return A [BatchSignOperation] instance containing the authenticated batch of
     * signing operations. The returned batch encapsulates the verified operations
     * that can be securely executed.
     */
    suspend fun authenticate(): BatchSignOperation<PUB>

    /**
     * Releases the resources associated with a batch of signing operations.
     *
     * This method is intended to clean up and release any allocated resources corresponding
     * to the provided batch of signing operations. It takes an optional `BatchSignOp` parameter
     * and ensures that any necessary cleanup for the batch is performed.
     *
     * @param signOps An optional [BatchSignOperation] instance containing the batch of signing operations
     *                to be released. If `null`, no operation is performed.
     */
    suspend fun release(signOps: BatchSignOperation<@UnsafeVariance PUB>?)

    companion object
}
