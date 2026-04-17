package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

internal class Signing private constructor(
    val algorithm: String,
) {
    fun sign(key: PrivateKey, signee: ByteArray): ByteArray {
        val sig = Signature.getInstance(algorithm)
        sig.initSign(key)
        sig.update(signee)
        return sig.sign()
    }

    fun verify(key: PublicKey, signee: ByteArray, signature: ByteArray) {
        val sig = Signature.getInstance(algorithm)
        sig.initVerify(key)
        sig.update(signee)
        if (!sig.verify(signature)) TODO("Signing:verify")
    }

    object ECDSA {
        val SHA256 = Signing(algorithm = "sha256withecdsa")
    }
}
