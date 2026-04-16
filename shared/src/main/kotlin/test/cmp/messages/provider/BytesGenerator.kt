package test.cmp.messages.provider

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import test.cmp.messages.entity.Argon2Specs

internal sealed interface BytesGenerator<T : Any> {
    fun generate(password: CharArray, specs: T): ByteArray

    object Argon2 : BytesGenerator<Argon2Specs> {
        override fun generate(
            password: CharArray,
            specs: Argon2Specs,
        ): ByteArray {
            val params = Argon2Parameters.Builder(specs.type)
                .withVersion(specs.version)
                .withSalt(specs.salt)
                .withIterations(specs.iterations)
                .withMemoryAsKB(specs.memorySize)
                .withParallelism(specs.parallelism)
                .build()
            val generator = Argon2BytesGenerator()
            generator.init(params)
            val bytes = ByteArray(specs.keySize)
            generator.generateBytes(password, bytes)
            return bytes
        }
    }
}
