package test.cmp.messages.provider

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
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
import java.security.spec.PKCS8EncodedKeySpec
import java.text.Normalizer
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.ECNamedCurveTable
import sp.kx.bytes.readUUID
import test.cmp.messages.entity.Argon2Specs
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.entity.SentryKey

internal class FinalSentry(
    private val aes: AESEncryption<GCMSpecs>,
    private val bg: BytesGenerator<Argon2Specs>,
    private val ec: ECCryptography,
    private val ecdh: KeyAgreements,
) : Sentry {
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
        val normalized = Normalizer.normalize(password, Normalizer.Form.NFKD)
        val keySpecs = Argon2Specs.V1(salt = nextBytes(32))
        val key = SecretKeySpec(bg.generate(normalized.toCharArray(), keySpecs), "aes")
        val specs = GCMSpecs(128, nextBytes(12))
        val encrypted = aes.encrypt(key, issuer.encoded, specs)
        val pub = getPublicKey(key = issuer)
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
        val pub = getPublicKey(key = pk)
        val md = MessageDigest.getInstance("sha256")
        val expected = md.digest(pub.encoded).readUUID()
        if (issuer.id != expected) TODO()
        return pk
    }

    override fun getSharedSecret(pk: PrivateKey): Pair<SecretKey, PublicKey> {
        val keyPair = ec.newKeyPair()
        val pub = getPublicKey(pk)
        val md = MessageDigest.getInstance("sha256")
        md.update(0x00)
        val key = SecretKeySpec(md.digest(ecdh.getSharedBytes(keyPair.private, pub)), "aes")
        return Pair(key, keyPair.public)
    }
}
