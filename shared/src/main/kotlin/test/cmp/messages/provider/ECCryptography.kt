package test.cmp.messages.provider

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import org.bouncycastle.jce.ECNamedCurveTable

internal class ECCryptography(name: String) {
    private val spec = ECNamedCurveTable.getParameterSpec(name)

    fun newKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("ec")
        kpg.initialize(ECGenParameterSpec(spec.name))
        return kpg.generateKeyPair()
    }

    fun getPublicKey(key: PrivateKey): PublicKey {
        check(key is ECPrivateKey)
        val generator = key.params.generator
        val p = spec.curve.createPoint(generator.affineX, generator.affineY)
        val point = spec
            .curve
            .multiplier
            .multiply(p, key.s)
            .normalize()
        val w = ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger())
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePublic(ECPublicKeySpec(w, key.params))
    }

    fun getPrivateKey(magnitude: ByteArray): PrivateKey {
        val ap = AlgorithmParameters.getInstance("ec")
        ap.init(ECGenParameterSpec(spec.name))
        val spec = ap.getParameterSpec(ECParameterSpec::class.java)
        val s = BigInteger(1, magnitude).mod(spec.order)
        val kf = KeyFactory.getInstance("ec")
        return kf.generatePrivate(ECPrivateKeySpec(s, spec))
    }
}
