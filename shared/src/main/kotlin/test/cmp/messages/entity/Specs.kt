package test.cmp.messages.entity

import org.bouncycastle.crypto.params.Argon2Parameters

internal sealed interface Specs

class GCMSpecs(val tagSize: Int, val iv: ByteArray) : Specs
class CBCSpecs(val iv: ByteArray) : Specs
class PBESpecs(val salt: ByteArray, val iterations: Int, val keySize: Int) : Specs
class Argon2Specs(
    val type: Int,
    val version: Int,
    val salt: ByteArray,
    val iterations: Int,
    val memorySize: Int,
    val parallelism: Int,
    val keySize: Int,
) : Specs {
    companion object {
        fun V1(salt: ByteArray, keySize: Int): Argon2Specs {
            if (salt.size != 32) TODO()
            return Argon2Specs(
                type = Argon2Parameters.ARGON2_id,
                version = Argon2Parameters.ARGON2_VERSION_13,
                salt = salt,
                iterations = 3,
                memorySize = 32_768,
                parallelism = 1,
                keySize = keySize,
            )
        }
    }
}
