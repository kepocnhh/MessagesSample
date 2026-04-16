package test.cmp.messages.entity

import java.util.UUID

internal class SentryKey(
    val id: UUID,
    val keySpecs: Argon2Specs,
    val specs: GCMSpecs,
    val encrypted: ByteArray,
)
