package test.cmp.messages.provider

import org.bouncycastle.crypto.params.Argon2Parameters
import sp.kx.bytes.hex
import sp.kx.bytes.readUUID
import sp.kx.hashes.Hashes
import sp.kx.secrets.Argon2Specs
import sp.kx.secrets.AsyKeys
import sp.kx.secrets.Bytes
import sp.kx.secrets.Ciphers
import sp.kx.secrets.GCMSpecs
import sp.kx.secrets.Keys
import sp.kx.secrets.Macs
import sp.kx.secrets.Shared
import sp.kx.secrets.Signing
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.SentryKey
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.text.Normalizer

internal class FinalSentry(
    private val random: SecureRandom,
    loggers: Loggers,
) : Sentry {
    private val logger = loggers.create("[Sentry]")
    private val ciphers = Ciphers.AES.GCM.NoPadding
    private val shared = Shared.ECDH
    private val signing = Signing.ECDSA.SHA256
    private val bytes = Bytes.Argon2
    private val macs = Macs.HMAC.SHA512
    private val ec = AsyKeys.EC.SECP256R1

    private fun Argon2Specs(salt: ByteArray, keySize: Int): Argon2Specs {
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
        val key = Keys.HMAC.SHA512.toSecretKey(sk)
        if (indices.size == 1) return macs.sign(key, signee)
        return derive(mk = macs.sign(key, signee), indices = indices.copyOfRange(1, indices.size))
    }

    private fun nextBytes(size: Int): ByteArray {
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
        val specs = Argon2Specs(salt = md.digest(), keySize = 64)
        return bytes.generate(password = normalized.toCharArray(), specs = specs)
    }

    override fun getPrivateKey(passphrase: String): PrivateKey {
        val seed = getSeed(passphrase = passphrase)
        logger.debug("seed(${seed.size}): ${seed.copyOf(8).hex()}")
        val magnitude = derive(mk = seed, indices = byteArrayOf(0x00), purpose = 0x00)
        logger.debug("magnitude(${magnitude.size}): ${magnitude.copyOf(8).hex()}")
        val pk = ec.getPrivateKey(magnitude = magnitude)
        logger.debug("pk: ${pk.encoded.toHexString()}")
        return pk
    }

    override fun toPublicKey(encoded: ByteArray): PublicKey {
        return AsyKeys.EC.toPublicKey(encoded = encoded)
    }

    override fun encrypt(
        password: String,
        issuer: PrivateKey,
    ): SentryKey {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val keySpecs = Argon2Specs(salt = nextBytes(32), keySize = 32)
        val key = Keys.AES.toSecretKey(bytes.generate(normalized.toCharArray(), keySpecs))
        val specs = GCMSpecs(128, nextBytes(12))
        val encrypted = ciphers.encrypt(key, issuer.encoded, specs)
        val pub = ec.getPublicKey(key = issuer)
        val id = Hashes.SHA256.digest(pub.encoded).readUUID()
        return SentryKey(
            id = id,
            keySpecs = keySpecs,
            specs = specs,
            encrypted = encrypted,
        )
    }

    override fun decrypt(
        password: String,
        issuer: SentryKey,
    ): PrivateKey {
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val key = Keys.AES.toSecretKey(bytes.generate(normalized.toCharArray(), issuer.keySpecs))
        val decrypted = ciphers.decrypt(key, issuer.encrypted, issuer.specs)
        val pk = AsyKeys.EC.toPrivateKey(decrypted)
        val pub = ec.getPublicKey(key = pk)
        val expected = Hashes.SHA256.digest(pub.encoded).readUUID()
        if (issuer.id != expected) TODO()
        return pk
    }

    override fun encrypt(key: PrivateKey, decrypted: ByteArray): CipherMessage {
        val pub = ec.getPublicKey(key = key)
        val keyPair = ec.newKeyPair(random = random)
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        val sb = shared.getSharedBytes(keyPair.private, pub)
        val sk = Keys.AES.toSecretKey(md.digest(sb))
        val signee = ByteArrayOutputStream().use { stream ->
            stream.writeBytes(key.encoded)
            stream.writeBytes(sk.encoded)
            stream.writeBytes(decrypted)
            stream.toByteArray()
        }
        val signature = signing.sign(key, signee)
        val specs = GCMSpecs(128, nextBytes(12))
        val encrypted = ciphers.encrypt(sk, decrypted, specs)
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
        val sb = shared.getSharedBytes(key, message.thatKey)
        val sk = Keys.AES.toSecretKey(md.digest(sb))
        val decrypted = ciphers.decrypt(sk, message.encrypted, message.specs)
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
