package main.java

import okio.*
import okio.ByteString.Companion.encode
import okio.HashingSink.Companion.sha256
import java.io.File
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.nio.charset.Charset
import kotlin.io.use
import okio.BufferedSource

import javax.crypto.spec.IvParameterSpec

import javax.crypto.spec.SecretKeySpec

import javax.crypto.Cipher

import java.io.IOException

import java.security.GeneralSecurityException

import okio.BufferedSink
import java.security.SecureRandom


/**
 * @author    yiliyang
 * @date      2021/4/22 下午4:33
 * @version   1.0
 * @since     1.0
 */
fun main() {
//    okipReadLine()
//    okioWriteLine()
//    println("中".utf8Size())
//    hashMethod()

//    blackHole()

//    aesTest()

    timeOut()
}

fun timeOut() {
    val file = File("test.txt")
}

fun aesTest() {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val randomSecureRandom = SecureRandom.getInstance("SHA1PRNG")
    val iv = ByteArray(cipher.blockSize)
    randomSecureRandom.nextBytes(iv)
    val file = File("test.txt")
    val key = "1234567812345678".toByteArray(Charset.defaultCharset())
    encryptAes(
        "yuliyang".encode(Charset.defaultCharset()),
        file,
        key,
        iv
    )

    println(
        decryptAesToByteString(
            file,
            key,
            iv
        ).toString()
    )
}

fun encryptAes(bytes: ByteString, file: File, key: ByteArray, iv: ByteArray) {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    val cipherSink = file.sink().cipherSink(cipher)
    cipherSink.buffer().use {
        it.write(bytes)
    }
}

fun decryptAesToByteString(file: File, key: ByteArray, iv: ByteArray): ByteString {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    val cipherSource = file.source().cipherSource(cipher)
    return cipherSource.buffer().use {
        it.readByteString()
    }
}


fun blackHole() {
    val file = File("test.txt")
//    sha256(blackholeSink()).use { hashingSink ->
//        file.source().buffer().use { source ->
//            source.readAll(hashingSink)
//            println("    sha256: " + hashingSink.hash.hex())
//        }
//    }

    sha256(blackholeSink()).use { hashingSink ->
        hashingSink.buffer().use { sink ->
            file.source().use { source ->
                sink.writeAll(source)
                sink.close() // Emit anything buffered.
                println("    sha256: " + hashingSink.hash.hex())
            }
        }
    }
}

fun hashMethod() {
    val byteString: ByteString = "yu".encode(Charset.defaultCharset())
    println("   md5: " + byteString.md5().hex())
    println("  sha1: " + byteString.sha1().hex())
    println("sha256: " + byteString.sha256().hex())
    println("sha512: " + byteString.sha512().hex())
}

fun okioWriteLine() {
    val file = File("test.txt")
    file.sink(append = true).buffer().writeUtf8("append").flush()
}

fun okipReadLine() {
    val file = File("test.txt")
    file.source().buffer().use { source ->
        generateSequence { source.readUtf8Line() }
            .filter { line -> "square" in line }
            .forEach(::println)
    }
}

@Throws(IOException::class)
private fun serialize(o: Any?): ByteString {
    val buffer = Buffer()
    ObjectOutputStream(buffer.outputStream()).use { objectOut ->
        objectOut.writeObject(o)
    }
    return buffer.readByteString()
}

@Throws(IOException::class, ClassNotFoundException::class)
private fun deserialize(byteString: ByteString): Any? {
    val buffer = Buffer()
    buffer.write(byteString)
    ObjectInputStream(buffer.inputStream()).use { objectIn ->
        return objectIn.readObject()
    }
}

//@Throws(IOException::class)
//fun encode(bitmap: Bitmap, sink: BufferedSink) {
//    val height = bitmap.height
//    val width = bitmap.width
//    val bytesPerPixel = 3
//    val rowByteCountWithoutPadding = bytesPerPixel * width
//    val rowByteCount = (rowByteCountWithoutPadding + 3) / 4 * 4
//    val pixelDataSize = rowByteCount * height
//    val bmpHeaderSize = 14
//    val dibHeaderSize = 40
//
//    // BMP Header
//    sink.writeUtf8("BM") // ID.
//    sink.writeIntLe(bmpHeaderSize + dibHeaderSize + pixelDataSize) // File size.
//    sink.writeShortLe(0) // Unused.
//    sink.writeShortLe(0) // Unused.
//    sink.writeIntLe(bmpHeaderSize + dibHeaderSize) // Offset of pixel data.
//
//    // DIB Header
//    sink.writeIntLe(dibHeaderSize)
//    sink.writeIntLe(width)
//    sink.writeIntLe(height)
//    sink.writeShortLe(1) // Color plane count.
//    sink.writeShortLe(bytesPerPixel * Byte.SIZE_BITS)
//    sink.writeIntLe(0) // No compression.
//    sink.writeIntLe(16) // Size of bitmap data including padding.
//    sink.writeIntLe(2835) // Horizontal print resolution in pixels/meter. (72 dpi).
//    sink.writeIntLe(2835) // Vertical print resolution in pixels/meter. (72 dpi).
//    sink.writeIntLe(0) // Palette color count.
//    sink.writeIntLe(0) // 0 important colors.
//
//    // Pixel data.
//    for (y in height - 1 downTo 0) {
//        for (x in 0 until width) {
//            sink.writeByte(bitmap.blue(x, y))
//            sink.writeByte(bitmap.green(x, y))
//            sink.writeByte(bitmap.red(x, y))
//        }
//
//        // Padding for 4-byte alignment.
//        for (p in rowByteCountWithoutPadding until rowByteCount) {
//            sink.writeByte(0)
//        }
//    }
//}