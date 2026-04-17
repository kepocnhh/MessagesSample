package test.cmp.messages.provider

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.text.Normalizer
import javax.crypto.spec.SecretKeySpec
import sp.kx.bytes.hex
import sp.kx.bytes.readUUID
import test.cmp.messages.entity.Argon2Specs
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.entity.SentryKey

internal class FinalSentry(
    loggers: Loggers,
) : Sentry {
    private val logger = loggers.create("[Sentry]")
    private val aes = AESSecrets.GCM.NoPadding
    private val ec = ECSecrets.SECP256R1
    private val ecdh = KeyAgreements.ECDH
    private val signing = Signing.ECDSA.SHA256
    private val bg = BytesGenerator.Argon2
    private val mac = Macs.HMAC.SHA512

    private fun derive(mk: ByteArray, indices: ByteArray, purpose: Byte): ByteArray {
        val sk = derive(mk = mk, indices = indices).copyOf(32)
        val md = MessageDigest.getInstance("sha256")
        md.update(purpose)
        return md.digest(sk)
    }

    private fun derive(mk: ByteArray, indices: ByteArray): ByteArray {
        val index = indices.firstOrNull() ?: TODO()
        val sk = mk.copyOf(32)
        val cc = mk.copyOfRange(32, 64)
        val md = MessageDigest.getInstance("sha256")
        md.update(index)
        val signee = md.digest(cc)
        val key = SecretKeySpec(sk, mac.algorithm)
        if (indices.size == 1) return mac.sign(key, signee)
        return derive(mk = mac.sign(key, signee), indices = indices.copyOfRange(1, indices.size))
    }

    private fun nextBytes(size: Int): ByteArray {
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }

    private fun getSeed(passphrase: String): ByteArray {
        logger.debug("passphrase(${passphrase.length}): \"$passphrase\"")
        val normalized = Normalizer.normalize(passphrase, Normalizer.Form.NFKD)
        logger.debug("normalized(${normalized.length}): \"$normalized\"")
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        md.update(normalized.toByteArray(Charsets.UTF_8))
        val specs = Argon2Specs.V1(salt = md.digest(), keySize = 64)
        return bg.generate(password = normalized.toCharArray(), specs = specs)
    }

    override fun getPrivateKey(passphrase: String): PrivateKey {
        val seed = getSeed(passphrase = passphrase)
        logger.debug("seed(${seed.size}): ${seed.copyOf(8).hex()}")
        val magnitude = derive(mk = seed, indices = byteArrayOf(0x00), purpose = 0x00)
        logger.debug("magnitude(${magnitude.size}): ${magnitude.copyOf(32).hex()}")
        val pk = ec.getPrivateKey(magnitude = magnitude)
        logger.debug("pk: ${pk.encoded.hex()}")
        return pk
    }

    override fun encrypt(
        password: String,
        issuer: PrivateKey,
    ): SentryKey {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val keySpecs = Argon2Specs.V1(salt = nextBytes(32), keySize = 32)
        val key = SecretKeySpec(bg.generate(normalized.toCharArray(), keySpecs), "aes")
        val specs = GCMSpecs(128, nextBytes(12))
        val encrypted = aes.encrypt(key, issuer.encoded, specs)
        val pub = ec.getPublicKey(key = issuer)
        val md = MessageDigest.getInstance("sha256")
        val id = md.digest(pub.encoded).readUUID()
        return SentryKey(
            id = id,
            keySpecs = keySpecs,
            specs = specs,
            encrypted = encrypted,
        )
    }

    private fun toPrivateKey(encoded: ByteArray): PrivateKey {
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePrivate(PKCS8EncodedKeySpec(encoded))
    }

    override fun decrypt(
        password: String,
        issuer: SentryKey,
    ): PrivateKey {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val key = SecretKeySpec(bg.generate(normalized.toCharArray(), issuer.keySpecs), "aes")
        val decrypted = aes.decrypt(key, issuer.encrypted, issuer.specs)
        val pk = toPrivateKey(decrypted)
        val pub = ec.getPublicKey(key = pk)
        val md = MessageDigest.getInstance("sha256")
        val expected = md.digest(pub.encoded).readUUID()
        if (issuer.id != expected) TODO()
        return pk
    }

    override fun encrypt(key: PrivateKey, decrypted: ByteArray): CipherMessage {
        val pub = ec.getPublicKey(key)
        val keyPair = ec.newKeyPair()
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        val sb = ecdh.getSharedBytes(keyPair.private, pub)
        val sk = SecretKeySpec(md.digest(sb), "aes")
        val signee = ByteArrayOutputStream().use { stream ->
            stream.writeBytes(key.encoded)
            stream.writeBytes(sk.encoded)
            stream.writeBytes(decrypted)
            stream.toByteArray()
        }
        val signature = signing.sign(key, signee)
        val specs = GCMSpecs(128, nextBytes(12))
        val encrypted = aes.encrypt(sk, decrypted, specs)
        return CipherMessage(
            thatKey = keyPair.public,
            specs = specs,
            encrypted = encrypted,
            signature = signature,
        )
    }

    override fun decrypt(key: PrivateKey, message: CipherMessage): ByteArray {
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        val sb = ecdh.getSharedBytes(key, message.thatKey)
        val sk = SecretKeySpec(md.digest(sb), "aes")
        val decrypted = aes.decrypt(sk, message.encrypted, message.specs)
        val signee = ByteArrayOutputStream().use { stream ->
            stream.writeBytes(key.encoded)
            stream.writeBytes(sk.encoded)
            stream.writeBytes(decrypted)
            stream.toByteArray()
        }
        val pub = ec.getPublicKey(key)
        signing.verify(pub, signee, message.signature)
        return decrypted
    }
}
