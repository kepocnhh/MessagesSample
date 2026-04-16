package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

internal sealed interface Signing {
    fun sign(key: PrivateKey, signee: ByteArray): ByteArray
    fun verify(key: PublicKey, signee: ByteArray, signature: ByteArray)

    object ECDSA {
        object SHA256 : Signing {
            override fun sign(key: PrivateKey, signee: ByteArray): ByteArray {
                val sig = Signature.getInstance("sha256withecdsa")
                sig.initSign(key)
                sig.update(signee)
                return sig.sign()
            }

            override fun verify(key: PublicKey, signee: ByteArray, signature: ByteArray) {
                val sig = Signature.getInstance("sha256withecdsa")
                sig.initVerify(key)
                sig.update(signee)
                if (!sig.verify(signature)) TODO("Signing:verify")
            }
        }
    }
}
