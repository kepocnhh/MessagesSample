package test.cmp.messages.entity

import java.util.UUID
import org.bouncycastle.crypto.params.Argon2Parameters

internal class SentryKey(
    val id: UUID,
    val params: Argon2Parameters,
    val gcm: GCMSpecs,
    val encrypted: ByteArray,
)
