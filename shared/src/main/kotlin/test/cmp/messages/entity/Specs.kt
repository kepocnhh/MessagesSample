package test.cmp.messages.entity

internal sealed interface Specs

class GCMSpecs(val tagSize: Int, val iv: ByteArray) : Specs
class CBCSpecs(val iv: ByteArray) : Specs
class PBESpecs(val salt: ByteArray, val iterations: Int, val keySize: Int) : Specs
class ArgonSpecs(
    val type: Int,
    val version: Int,
    val salt: ByteArray,
    val iterations: Int,
    val memorySize: Int,
    val parallelism: Int,
    val keySize: Int,
) : Specs
