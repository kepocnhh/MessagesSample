package test.cmp.messages.entity

import java.io.InputStream

internal class HttpResponse(
    val version: String,
    val code: Int,
    val message: String,
    val headers: Map<String, String>,
    val body: InputStream,
)
