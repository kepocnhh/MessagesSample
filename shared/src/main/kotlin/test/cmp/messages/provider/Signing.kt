package test.cmp.messages.provider

import java.security.PrivateKey
import java.security.PublicKey

internal interface Signing {
    fun sign(key: PrivateKey, signee: ByteArray): ByteArray
    fun verify(key: PublicKey, signee: ByteArray, signature: ByteArray)
}
