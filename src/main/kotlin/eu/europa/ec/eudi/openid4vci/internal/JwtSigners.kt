package eu.europa.ec.eudi.openid4vci.internal

import eu.europa.ec.eudi.openid4vci.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.*

internal class JwtProofSigner(
    private val signOp: SignOp<JwtBindingKey>,
    private val assertions: SignOp<JwtBindingKey>.() -> Unit = {},
) {
    suspend fun sign(claims: JwtProofClaims): String =
        JwtSigner<JwtProofClaims, JwtBindingKey>(
            signOp = signOp,
            customizeHeader = { pubKey -> jwtProofHeader(pubKey) },
            assertions  = assertions,
        ).sign(claims)
}

internal class JwtProofsSigner(
    private val batchSignOp: BatchSignOp<JwtBindingKey>,
    private val assertions: SignOp<JwtBindingKey>.() -> Unit = {},
) {
    suspend fun sign(claims: JwtProofClaims): List<String> =
        JwtBatchSigner<JwtProofClaims, JwtBindingKey>(
            signOps = batchSignOp,
            customizeHeader = { pubKey -> jwtProofHeader(pubKey) },
            assertions = assertions,
        ).sign(claims)
}

internal fun JsonObjectBuilder.jwtProofHeader(key: JwtBindingKey) {
    put("typ", "openid4vci-proof+jwt")
    when (key) {
        is JwtBindingKey.Did -> {
            put("kid", key.identity)
        }
        is JwtBindingKey.Jwk -> {
            put("jwk", key.jwk.asJsonElement())
        }
        is JwtBindingKey.X509 -> {
            put("x5c", key.chain.asJsonElement())
        }
    }
}