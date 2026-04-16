package test.cmp.messages.provider

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.text.Normalizer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.jce.ECNamedCurveTable
import sp.kx.bytes.readUUID
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
        val ap = AlgorithmParameters.getInstance("ec")
        ap.init(ECGenParameterSpec("secp256r1"))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val s = BigInteger(1, seed).mod(spec.order)
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePrivate(ECPrivateKeySpec(s, spec))
    }

    private fun getPublicKey(key: PrivateKey): PublicKey {
        check(key is ECPrivateKey)
        val curve = ECNamedCurveTable.getParameterSpec("secp256r1").curve
        val point = curve
            .multiplier
            .multiply(curve.createPoint(key.params.generator.affineX, key.params.generator.affineY), key.s)
            .normalize()
        val w = ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger())
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePublic(ECPublicKeySpec(w, key.params))
    }

    override fun encrypt(
        password: String,
        issuer: PrivateKey,
    ): SentryKey {
        val encoded = Normalizer
            .normalize(password, Normalizer.Form.NFKD)
            .toByteArray(Charsets.UTF_8)
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        val salt = ByteArray(32)
        random.nextBytes(salt)
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(3)
            .withMemoryAsKB(32_768)
            .withParallelism(1)
            .build()
        val generator = Argon2BytesGenerator()
        generator.init(params)
        val seed = ByteArray(32)
        generator.generateBytes(encoded, seed)
        val key = SecretKeySpec(seed, "aes")
        val iv = ByteArray(12)
        random.nextBytes(iv)
        val spec = GCMParameterSpec(128, iv)
        val cipher = Cipher.getInstance("aes/gcm/nopadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        val encrypted = cipher.doFinal(issuer.encoded)
        val pub = getPublicKey(key = issuer)
        val md = MessageDigest.getInstance("sha256")
        val id = md.digest(pub.encoded).readUUID()
        return SentryKey(
            id = id,
            params = params,
            spec = spec,
            encrypted = encrypted,
        )
    }

    override fun decrypt(
        password: String,
        issuer: SentryKey,
    ): PrivateKey {
        TODO("Sentry:decrypt")
    }
}
