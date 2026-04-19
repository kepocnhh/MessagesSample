package test.cmp.messages.entity

internal class HttpRequest(
    val version: String,
    val method: String,
    val query: String,
    val headers: Map<String, String>,
    val body: ByteArray?,
)
