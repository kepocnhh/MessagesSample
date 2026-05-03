package test.cmp.messages.entity

import java.util.UUID
import kotlin.time.Duration

internal class DecryptedRequest(
    val id: UUID,
    val code: Int,
    val time: Duration,
    val body: ByteArray,
)
