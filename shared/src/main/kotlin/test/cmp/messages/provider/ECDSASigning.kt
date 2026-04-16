package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

internal class ECDSASigning(
    private val hash: String,
) : Signing {
    override fun sign(key: PrivateKey, signee: ByteArray): ByteArray {
        val sig = Signature.getInstance("${hash}withecdsa")
        sig.initSign(key)
        sig.update(signee)
        return sig.sign()
    }

    override fun verify(key: PublicKey, signee: ByteArray, signature: ByteArray) {
        val sig = Signature.getInstance("${hash}withecdsa")
        sig.initVerify(key)
        sig.update(signee)
        if (!sig.verify(signature)) TODO("Signing:verify")
    }
}
