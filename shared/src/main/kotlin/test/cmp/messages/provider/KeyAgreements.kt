package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.KeyAgreement

internal interface KeyAgreements {
    fun getSharedBytes(thisKey: PrivateKey, thatKey: PublicKey): ByteArray

    companion object {
        val ECDH = object : KeyAgreements {
            override fun getSharedBytes(thisKey: PrivateKey, thatKey: PublicKey): ByteArray {
                val ka = KeyAgreement.getInstance("ecdh")
                ka.init(thisKey)
                ka.doPhase(thatKey, true)
                return ka.generateSecret()
            }
        }
    }
}
