import ShiftTo.ByteArrayToBigInteger
import ShiftTo.ByteArrayToHex
import ShiftTo.DeciToHex
import ShiftTo.HexToByteArray
import ShiftTo.SHA256

import ecc.ECPublicKey.toPoint
import ecc.EllipticCurve.multiplyPoint
import signature.Schnorr
import signature.Schnorr.generateAuxRand
import java.math.BigInteger

fun main() {

    val privateKey: BigInteger = generateAuxRand().ByteArrayToBigInteger()
    val message: ByteArray = "I am a fish".SHA256()

    val xValue: ByteArray = privateKey.toPoint().x.DeciToHex().HexToByteArray() // PublicKey x value

    val ran: ByteArray = "77c179f9076085a8a317c1fcd6f67327a35c1add0efe303a53883533fcb88f80".HexToByteArray()
    //val ran: ByteArray = generateAuxRand()

    println("Random: ${ran.size} ${ran.ByteArrayToHex()}")
    val signature: String = Schnorr.sign(privateKey, message.ByteArrayToBigInteger(), ran)
    val verify: Boolean = Schnorr.verify(message, xValue, signature)

    println("Public key point: ${multiplyPoint(privateKey)}")
    println("Message: ${message.ByteArrayToHex()}")

    println("\nPrivate Key: ${privateKey.DeciToHex()} size ${privateKey.DeciToHex().HexToByteArray().size} bytes")
    println("Public Key X: ${privateKey.toPoint().x.toString(16)}")

    println("Signature size ${signature.HexToByteArray().size} bytes: $signature")
    println("Verify Signature: $verify")

}