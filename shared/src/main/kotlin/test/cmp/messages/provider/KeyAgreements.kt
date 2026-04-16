package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

internal class KeyAgreements private constructor(
    private val algorithm: String,
) {
    fun getSharedBytes(thisKey: PrivateKey, thatKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance(algorithm)
        ka.init(thisKey)
        ka.doPhase(thatKey, true)
        return ka.generateSecret()
    }

    companion object {
        val ECDH = KeyAgreements(algorithm = "ecdh")
    }
}
