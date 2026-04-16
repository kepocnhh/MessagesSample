package test.cmp.messages.provider

import test.cmp.messages.entity.Argon2Specs
import test.cmp.messages.entity.CBCSpecs
import test.cmp.messages.entity.GCMSpecs
import test.cmp.messages.entity.PBESpecs

internal class AESCryptography(
    val gcm: AESEncryption<GCMSpecs>,
    val cbc: AESEncryption<CBCSpecs>,
    val pbe: AESGenerator<PBESpecs>,
    val argon2: AESGenerator<Argon2Specs>,
)
