package test.cmp.messages.provider

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement

internal class ECCryptography(
    private val curve: String,
) {
    fun newKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("ec")
        kpg.initialize(ECGenParameterSpec(curve))
        return kpg.generateKeyPair()
    }
}
