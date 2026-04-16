package test.cmp.messages.entity

import java.util.UUID

internal class SentryKey(
    val id: UUID,
    val argon2: Argon2Specs,
    val gcm: GCMSpecs,
    val encrypted: ByteArray,
)
