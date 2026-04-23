package test.cmp.messages.provider

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import sp.kx.bytes.readBytes
import sp.kx.bytes.readInt
import sp.kx.bytes.readUUID
import sp.kx.bytes.writeBytes
import sp.kx.secrets.Argon2Specs
import sp.kx.secrets.GCMSpecs
import test.cmp.messages.entity.SentryKey

internal class FinalLocals : Locals {
    private var bytes: ByteArray? = null

    override var sk: SentryKey?
        get() {
            if (bytes == null) return null
            return ByteArrayInputStream(bytes).use { stream ->
                SentryKey(
                    id = stream.readUUID(),
                    keySpecs = Argon2Specs(
                        type = stream.read(),
                        version = stream.read(),
                        salt = stream.readBytes(stream.read()),
                        iterations = stream.readInt(),
                        memorySize = stream.readInt(),
                        parallelism = stream.read(),
                        keySize = stream.read(),
                    ),
                    specs = GCMSpecs(
                        tagSize = stream.read(),
                        iv = stream.readBytes(stream.read()),
                    ),
                    encrypted = stream.readBytes(stream.readInt()),
                )
            }
        }
        set(value) {
            if (value == null) {
                bytes = null
            } else {
                bytes = ByteArrayOutputStream().use { stream ->
                    stream.writeBytes(value.id)
                    //
                    stream.write(value.keySpecs.type)
                    stream.write(value.keySpecs.version)
                    stream.write(value.keySpecs.salt.size)
                    stream.writeBytes(value.keySpecs.salt)
                    stream.writeBytes(value.keySpecs.iterations)
                    stream.writeBytes(value.keySpecs.memorySize)
                    stream.write(value.keySpecs.parallelism)
                    stream.write(value.keySpecs.keySize)
                    //
                    stream.write(value.specs.tagSize)
                    stream.write(value.specs.iv.size)
                    stream.writeBytes(value.specs.iv)
                    //
                    stream.writeBytes(value.encrypted.size)
                    stream.writeBytes(value.encrypted)
                    //
                    stream.toByteArray()
                }
            }
        }

    override var pk: PrivateKey? = null
}
