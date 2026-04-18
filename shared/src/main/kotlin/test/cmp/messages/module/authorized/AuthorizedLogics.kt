package test.cmp.messages.module.authorized

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.NetworkInterface
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import sp.kx.bytes.readBytes
import sp.kx.bytes.readInt
import sp.kx.bytes.readLong
import sp.kx.bytes.toByteArray
import sp.kx.bytes.writeBytes
import sp.kx.logics.Logics
import test.cmp.messages.entity.CipherMessage
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.provider.Providers

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

    fun receive() = launch {
        logger.debug("receive")
        withContext(providers.contexts.default) {
            for (ni in NetworkInterface.getNetworkInterfaces()) {
                logger.debug("ni: ${ni.name}")
                for (address in ni.inetAddresses) {
                    val message = """
                        hostName: ${address.hostName}
                        hostAddress: ${address.hostAddress}
                        isAnyLocalAddress: ${address.isAnyLocalAddress}
                        isLinkLocalAddress: ${address.isLinkLocalAddress}
                        isLoopbackAddress: ${address.isLoopbackAddress}
                        isMCGlobal: ${address.isMCGlobal}
                        isMCLinkLocal: ${address.isMCLinkLocal}
                        isMCNodeLocal: ${address.isMCNodeLocal}
                        isMCOrgLocal: ${address.isMCOrgLocal}
                        isMulticastAddress: ${address.isMulticastAddress}
                        isSiteLocalAddress: ${address.isSiteLocalAddress}
                    """.trimIndent()
                    logger.debug(message)
                }
            }
        }
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
            ByteArrayOutputStream().use { stream ->
                stream.writeBytes(cm.thatKey.encoded.size)
                stream.writeBytes(cm.thatKey.encoded)
                stream.write(cm.specs.tagSize)
                stream.write(cm.specs.iv.size)
                stream.writeBytes(cm.specs.iv)
                stream.writeBytes(cm.encrypted.size)
                stream.writeBytes(cm.encrypted)
                stream.write(cm.signature.size)
                stream.writeBytes(cm.signature)
                stream.toByteArray()
            }
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
                val cm = ByteArrayInputStream(message).use { stream ->
                    CipherMessage(
                        thatKey = providers.sentry.toPublicKey(stream.readBytes(stream.readInt())),
                        specs = GCMSpecs(
                            tagSize = stream.read(),
                            iv = stream.readBytes(stream.read()),
                        ),
                        encrypted = stream.readBytes(stream.readInt()),
                        signature = stream.readBytes(stream.read()),
                    )
                }
                val decrypted = providers.sentry.decrypt(pk, message = cm)
                decrypted.readLong()
            }
        }
        _loading.value = false
        _events.emit(Event.OnDecrypt(result))
    }
}
