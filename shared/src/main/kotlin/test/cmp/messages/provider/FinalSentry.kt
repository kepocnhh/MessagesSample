package test.cmp.messages.provider

import java.security.MessageDigest
import java.security.PrivateKey
import java.text.Normalizer
import javax.crypto.SecretKey
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import test.cmp.messages.entity.SentryKey

internal class FinalSentry : Sentry {
    private fun getSeed(passphrase: String): ByteArray {
        val encoded = Normalizer
            .normalize(passphrase, Normalizer.Form.NFKD)
            .toByteArray(Charsets.UTF_8)
        val type = Argon2Parameters.ARGON2_id
        val version = Argon2Parameters.ARGON2_VERSION_13
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        md.update(encoded)
        val salt = md.digest()
        val iterations = 3
        val mem = 32_768
        val parallelism = 1
        val params = Argon2Parameters.Builder(type)
            .withVersion(version)
            .withSalt(salt)
            .withIterations(iterations)
            .withMemoryAsKB(mem)
            .withParallelism(parallelism)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(params)
        val seed = ByteArray(32)
        generator.generateBytes(encoded, seed)
        return seed
    }

    override fun getPrivateKey(passphrase: String): PrivateKey {
        val seed = getSeed(passphrase = passphrase)
        TODO("Sentry:getPrivateKey")
    }

    override fun encrypt(
        sk: SecretKey,
        issuer: PrivateKey,
    ): SentryKey {
        TODO("Sentry:encrypt")
    }

    override fun decrypt(
        sk: SecretKey,
        issuer: SentryKey,
    ): PrivateKey {
        TODO("Sentry:decrypt")
    }
}
