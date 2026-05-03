package test.cmp.messages.module.authorized

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.NetworkInterface
import java.net.ServerSocket
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import sp.kx.bytes.readBytes
import sp.kx.bytes.readInt
import sp.kx.bytes.readLong
import sp.kx.bytes.readUntil
import sp.kx.bytes.toByteArray
import sp.kx.bytes.writeBytes
import sp.kx.logics.Logics
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.HttpRequest
import test.cmp.messages.entity.HttpResponse
import test.cmp.messages.provider.Providers
import java.net.Inet4Address
import okhttp3.RequestBody.Companion.toRequestBody
import sp.kx.bytes.readUUID
import sp.kx.hashes.Hashes
import sp.kx.secrets.GCMSpecs

internal class AuthorizedLogics(
    private val providers: Providers,
) : Logics(providers.contexts.main) {
    sealed interface Event {
        data object OnLock : Event
        class OnEncrypt(val message: ByteArray) : Event
        class OnDecrypt(val result: Result<Long>) : Event
    }

    private val logger = providers.loggers.create("[Authorized]")
    private val _events = MutableSharedFlow<Event>()
    val events: Flow<Event> = _events.asSharedFlow()
    private val _loading = MutableStateFlow(false)
    val loading = _loading.asStateFlow()

    fun lock() = launch {
        logger.debug("lock")
        _loading.value = true
        withContext(providers.contexts.default) {
            providers.locals.pk = null
        }
        _events.emit(Event.OnLock)
    }

    private fun read(src: InputStream): HttpRequest {
        val separator = "\r\n".toByteArray(Charsets.UTF_8)
        val firstLine = src.readUntil(until = separator).toString(Charsets.UTF_8)
        val split = firstLine.split(" ")
        if (split.size != 3) TODO()
        val protocol = split[2].split("/")
        if (protocol.size != 2) TODO()
        if (protocol[0] != "HTTP") TODO()
        val version = protocol[1]
        if (version != "1.1") TODO()
        val method = split[0]
        val query = split[1]
        val headers = mutableMapOf<String, String>()
        while (true) {
            val line = src.readUntil(until = separator).toString(Charsets.UTF_8)
            if (line.isEmpty()) break
            val colonIndex = line.indexOf(':')
            if (colonIndex < 1) continue
            if (colonIndex > line.length - 3) continue
            val key = line.substring(0, colonIndex)
            val value = line.substring(colonIndex + 2, line.length)
            headers[key] = value
        }
        return HttpRequest(
            version = version,
            method = method,
            query = query,
            headers = headers,
            body = src,
        )
    }

    private fun write(dst: OutputStream, response: HttpResponse) {
        val separator = "\r\n".toByteArray(Charsets.UTF_8)
        dst.write("HTTP/${response.version} ${response.code} ${response.message}".toByteArray(Charsets.UTF_8))
        dst.write(separator)
        response.headers.forEach { (key, value) ->
            dst.write("$key: $value".toByteArray(Charsets.UTF_8))
            dst.write(separator)
        }
        dst.write(separator)
        val length = response.headers["Content-Length"]?.toIntOrNull() ?: -1
        for (index in 0 until length) {
            val value = response.body.read()
            if (value == -1) TODO()
            dst.write(value)
        }
        dst.flush()
    }

    private fun route(request: HttpRequest): HttpResponse {
        when (request.query) {
            "/message" -> {
                val pk = providers.locals.pk ?: error("No private key!")
                val cm = request.body.toCipherMessage()
                val decrypted = providers.sentry.decrypt(pk, message = cm)
                val time = decrypted.readLong()
                logger.debug("receive:time: $time")
                return HttpResponse(
                    version = "1.1",
                    code = 200,
                    message = "OK",
                    headers = mapOf(),
                    body = ByteArray(0).inputStream(),
                )
            }
            else -> return HttpResponse(
                version = "1.1",
                code = 500,
                message = "Internal Server Error",
                headers = mapOf(),
                body = ByteArray(0).inputStream(),
            )
        }
        val body = request.headers["Content-Length"]
            ?.toIntOrNull()
            ?.takeIf { it > 0 }
            ?.let(request.body::readBytes)
            ?.let(::String)
        val message = """
            headers: ${request.headers}
            body(${body?.length}): $body
        """.trimIndent()
        logger.debug(message)
        val text = """{"millis": ${System.currentTimeMillis()}}"""
        val bytes = text.toByteArray(Charsets.UTF_8)
        return HttpResponse(
            version = "1.1",
            code = 200,
            message = "OK",
            headers = mapOf(
                "Content-Type" to "application/json",
                "Content-Length" to "${bytes.size}",
            ),
            body = bytes.inputStream(),
        )
    }

    fun receive(code: Int) = launch {
        logger.debug("receive")
        withContext(providers.contexts.default) {
            runCatching {
                val address = NetworkInterface.getNetworkInterfaces()
                    ?.asSequence()
                    ?.flatMap { it.inetAddresses.asSequence() }
                    ?.firstOrNull { it is Inet4Address && !it.isLoopbackAddress && it.isSiteLocalAddress }
                    ?: TODO("No address!")
                val sessionId = Hashes.SHA256.update(0x00).digest(code.toByteArray()).readUUID()
                val port = 56934 // todo
                val ss = ServerSocket(port, 1, address)
                logger.debug("socket: ${ss.inetAddress.hostAddress}:${ss.localPort}")
                launch {
                    withContext(providers.contexts.default) {
                        delay(32.seconds)
                        logger.debug("try to close the socket")
                        ss.close()
                    }
                }
                while (true) {
                    ss.accept().use { socket ->
                        logger.debug("socket:accept: ${socket.inetAddress.hostAddress}:${socket.port}")
                        val request = read(socket.getInputStream())
                        val response = route(request)
                        write(socket.getOutputStream(), response)
                    }
                }
            }.fold(
                onSuccess = {
                    logger.debug("receive success")
                },
                onFailure = { error ->
                    logger.warning("receive error: $error")
                },
            )
        }
    }

    fun transmit(address: String) = launch {
        logger.debug("transmit: $address")
        withContext(providers.contexts.default) {
            val pk = providers.locals.pk ?: error("No private key!")
            val time = System.currentTimeMillis()
            logger.debug("transmit:time: $time")
            val decrypted = time.toByteArray()
            val cm = providers.sentry.encrypt(pk, decrypted = decrypted)
            runCatching {
                //
                val client = OkHttpClient.Builder().build()
                val body = cm.toByteArray().toRequestBody()
                val request = Request.Builder()
                    .url("$address/message")
                    .post(body)
                    .build()
                client.newCall(request).execute().use { response ->
                    val message = """
                        code: ${response.code}
                        message: ${response.message}
                        headers: ${response.headers.toMap()}
                        body: ${response.body.string()}
                    """.trimIndent()
                    logger.debug(message)
                }
            }.fold(
                onSuccess = {
                    logger.debug("transmit($address) success")
                },
                onFailure = { error ->
                    logger.warning("transmit($address) error: $error")
                },
            )
        }
    }

    private fun CipherMessage.toByteArray(): ByteArray {
        val stream = ByteArrayOutputStream()
        stream.writeBytes(thatKey.encoded.size)
        stream.writeBytes(thatKey.encoded)
        stream.write(specs.tagSize)
        stream.write(specs.iv.size)
        stream.writeBytes(specs.iv)
        stream.writeBytes(encrypted.size)
        stream.writeBytes(encrypted)
        stream.write(signature.size)
        stream.writeBytes(signature)
        return stream.toByteArray()
    }

    private fun InputStream.toCipherMessage(): CipherMessage {
        return CipherMessage(
            thatKey = providers.sentry.toPublicKey(readBytes(readInt())),
            specs = GCMSpecs(
                tagSize = read(),
                iv = readBytes(read()),
            ),
            encrypted = readBytes(readInt()),
            signature = readBytes(read()),
        )
    }

    fun encrypt() = launch {
        logger.debug("encrypt")
        _loading.value = true
        val message = withContext(providers.contexts.default) {
            val pk = providers.locals.pk ?: error("No private key!")
            val time = System.currentTimeMillis()
            logger.debug("time: $time")
            val decrypted = time.toByteArray()
            val cm = providers.sentry.encrypt(pk, decrypted = decrypted)
            cm.toByteArray()
        }
        _loading.value = false
        _events.emit(Event.OnEncrypt(message = message))
    }

    fun decrypt(message: ByteArray) = launch {
        logger.debug("decrypt")
        _loading.value = true
        val result = withContext(providers.contexts.default) {
            val pk = providers.locals.pk ?: error("No private key!")
            runCatching {
                val cm = ByteArrayInputStream(message).toCipherMessage()
                val decrypted = providers.sentry.decrypt(pk, message = cm)
                decrypted.readLong()
            }
        }
        _loading.value = false
        _events.emit(Event.OnDecrypt(result))
    }
}
