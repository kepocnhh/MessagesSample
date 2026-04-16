package test.cmp.messages.provider

import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.text.Normalizer
import javax.crypto.spec.SecretKeySpec
import sp.kx.bytes.readUUID
import test.cmp.messages.entity.Argon2Specs
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.entity.SentryKey

internal class FinalSentry : Sentry {
    private val aes = AESSecrets.GCM.NoPadding
    private val ec = ECSecrets.SECP256R1
    private val ecdh = KeyAgreements.ECDH
    private val signing = Signing.ECDSA.SHA256
    private val bg = BytesGenerator.Argon2

    private fun nextBytes(size: Int): ByteArray {
        val random: SecureRandom = SecureRandom.getInstanceStrong()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }

    private fun getSeed(passphrase: String): ByteArray {
        val normalized = Normalizer.normalize(passphrase, Normalizer.Form.NFKD)
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        val specs = Argon2Specs.V1(salt = md.digest(normalized.toByteArray(Charsets.UTF_8)))
        return bg.generate(password = normalized.toCharArray(), specs = specs)
    }

    override fun getPrivateKey(passphrase: String): PrivateKey {
        val seed = getSeed(passphrase = passphrase)
        return ec.getPrivateKey(magnitude = seed)
    }

    override fun encrypt(
        password: String,
        issuer: PrivateKey,
    ): SentryKey {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val keySpecs = Argon2Specs.V1(salt = nextBytes(32))
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
