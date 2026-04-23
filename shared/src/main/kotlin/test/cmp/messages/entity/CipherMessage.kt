package test.cmp.messages.entity

import sp.kx.secrets.GCMSpecs
import java.security.PublicKey

internal class CipherMessage(
    val thatKey: PublicKey,
    val specs: GCMSpecs,
    val encrypted: ByteArray,
    val signature: ByteArray,
)
