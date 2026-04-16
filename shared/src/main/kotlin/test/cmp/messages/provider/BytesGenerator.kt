package test.cmp.messages.provider

import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import test.cmp.messages.entity.Argon2Specs
import test.cmp.messages.entity.PBESpecs

internal interface BytesGenerator<T : Any> {
    fun generate(password: CharArray, specs: T): ByteArray

    companion object {
        val PBE = object : BytesGenerator<PBESpecs> {
            override fun generate(
                password: CharArray,
                specs: PBESpecs,
            ): ByteArray {
                val keyFactory = SecretKeyFactory.getInstance("pbkdf2withhmacsha256")
                val keySpec = PBEKeySpec(password, specs.salt, specs.iterations, specs.keySize)
                return keyFactory.generateSecret(keySpec).encoded
            }
        }

        val Argon2 = object : BytesGenerator<Argon2Specs> {
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
}
