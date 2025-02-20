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

import eu.europa.ec.eudi.openid4vci.ClaimPathElement.*
import eu.europa.ec.eudi.openid4vci.internal.ClaimPathSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

//
// That's a copy from sd-jwt-kt lib
//

/**
 * The path is a non-empty [list][value] of [elements][ClaimPathElement],
 * null values, or non-negative integers.
 * It is used to [select][SelectPath] a particular claim in the credential or a set of claims.
 *
 * It is [serialized][ClaimPathSerializer] as a [JsonArray] which may contain
 * string, `null`, or integer elements
 */
@Serializable(with = ClaimPathSerializer::class)
@JvmInline
value class ClaimPath(val value: List<ClaimPathElement>) {

    init {
        require(value.isNotEmpty())
    }

    override fun toString(): String = value.toString()

    operator fun plus(other: ClaimPathElement): ClaimPath = ClaimPath(this.value + other)

    operator fun plus(other: ClaimPath): ClaimPath = ClaimPath(this.value + other.value)

    operator fun contains(that: ClaimPath): Boolean = value.foldIndexed(this.value.size <= that.value.size) { index, acc, thisElement ->
        fun comp() = that.value.getOrNull(index)?.let { thatElement -> thatElement in thisElement } == true
        acc and comp()
    }

    /**
     * Appends a wild-card indicator [ClaimPathElement.AllArrayElements]
     */
    fun allArrayElements(): ClaimPath = this + AllArrayElements

    /**
     * Appends an indexed path [ClaimPathElement.ArrayElement]
     */
    fun arrayElement(i: Int): ClaimPath = this + ArrayElement(i)

    /**
     * Appends a named path [ClaimPathElement.Claim]
     */
    fun claim(name: String): ClaimPath = this + Claim(name)

    /**
     * Gets the ClaimPath of the parent element. Returns `null` to indicate the root element.
     */
    fun parent(): ClaimPath? = value.dropLast(1)
        .takeIf { it.isNotEmpty() }
        ?.let { ClaimPath(it) }

    fun head(): ClaimPathElement = value.first()
    fun tail(): ClaimPath? {
        val tailElements = value.drop(1)
        return if (tailElements.isEmpty()) return null
        else ClaimPath(tailElements)
    }

    /**
     * Gets the [head]
     */
    operator fun component1(): ClaimPathElement = head()

    /**
     * Gets the [tail]
     */
    operator fun component2(): ClaimPath? = tail()

    companion object {
        fun claim(name: String): ClaimPath = ClaimPath(listOf(Claim(name)))
    }
}

/**
 * Elements of a [ClaimPath]
 * - [Claim] indicates that the respective [key][Claim.name] is to be selected
 * - [AllArrayElements] indicates that all elements of the currently selected array(s) are to be selected, and
 * - [ArrayElement] indicates that the respective [index][ArrayElement.index] in an array is to be selected
 */
sealed interface ClaimPathElement {

    /**
     * Indicates that all elements of the currently selected array(s) are to be selected
     * It is serialized as a [JsonNull]
     */
    data object AllArrayElements : ClaimPathElement {
        override fun toString(): String = "null"
    }

    /**
     * Indicates that the respective [index][index] in an array is to be selected.
     * It is serialized as an [integer][JsonPrimitive]
     * @param index Non-negative index
     */
    @JvmInline
    value class ArrayElement(val index: Int) : ClaimPathElement {
        init {
            require(index >= 0) { "Index should be non-negative" }
        }

        override fun toString(): String = index.toString()
    }

    /**
     * Indicates that the respective [key][name] is to be selected.
     * It is serialized as a [string][JsonPrimitive]
     * @param name the attribute name
     */
    @JvmInline
    value class Claim(val name: String) : ClaimPathElement {
        override fun toString(): String = name
    }

    /**
     * Indication of whether the current instance contains the other.
     * @param that the element to compare with
     * @return in case that the two elements are of the same type, and if they are equal (including attribute),
     * then true is being returned. Also, an [AllArrayElements] contains [ArrayElement].
     * In all other cases, a false is being returned.
     */
    operator fun contains(that: ClaimPathElement): Boolean = when (this) {
        AllArrayElements -> when (that) {
            AllArrayElements -> true
            is ArrayElement -> true
            is Claim -> false
        }

        is ArrayElement -> this == that
        is Claim -> this == that
    }
}

@OptIn(ExperimentalContracts::class)
inline fun <T> ClaimPathElement.fold(
    ifAllArrayElements: () -> T,
    ifArrayElement: (Int) -> T,
    ifClaim: (String) -> T,
): T {
    contract {
        callsInPlace(ifAllArrayElements, InvocationKind.AT_MOST_ONCE)
        callsInPlace(ifArrayElement, InvocationKind.AT_MOST_ONCE)
        callsInPlace(ifClaim, InvocationKind.AT_MOST_ONCE)
    }
    return when (this) {
        AllArrayElements -> ifAllArrayElements()
        is ArrayElement -> ifArrayElement(index)
        is ClaimPathElement.Claim -> ifClaim(name)
    }
}

fun JsonArray.asClaimPath(): ClaimPath {
    val elements = map {
        require(it is JsonPrimitive)
        it.asClaimPathElement()
    }
    return ClaimPath(elements)
}

fun JsonPrimitive.asClaimPathElement(): ClaimPathElement = when {
    this is JsonNull -> AllArrayElements
    isString -> Claim(content)
    intOrNull != null -> ArrayElement(int)
    else -> throw IllegalArgumentException("Only string, null, int can be used")
}
