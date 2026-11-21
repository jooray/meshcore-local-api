package io.github.jooray.meshcore.localapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Locale

/**
 * Where the app keeps its pairing key between runs. The stored string is the JSON
 * `{"private":"<base64 PKCS#8>","public":"<base64 X||Y>"}` that LibreTag, the Nostr bridge and
 * Roadbeacon already write, so an app that switches to this library keeps its pairing.
 */
interface KeyStore {
    fun load(): String?
    fun save(value: String)
}

/** A [KeyStore] that forgets everything when the process ends (tests, tools). */
class InMemoryKeyStore(private var value: String? = null) : KeyStore {
    @Synchronized override fun load(): String? = value
    @Synchronized override fun save(value: String) { this.value = value }
}

/**
 * The app's P-256 key: its identity towards the Local API server. The private key never leaves
 * this object except in [encode], which is what a [KeyStore] persists.
 */
class ClientIdentity private constructor(
    private val privateKey: PrivateKey,
    /** The raw public point X||Y, 64 bytes. */
    val publicKeyRaw: ByteArray,
) {
    init {
        require(publicKeyRaw.size == 64) { "public key must be 64 bytes X||Y" }
    }

    /** Base64 of [publicKeyRaw], as sent in `hello.client.publicKey`. */
    val publicKeyBase64: String get() = Base64.getEncoder().encodeToString(publicKeyRaw)

    /**
     * What the server shows in its approval dialog: the first 8 bytes of SHA-256 over the raw
     * public key, upper-case hex in groups of four, e.g. `AB12 CD34 EF56 7890`.
     */
    val fingerprint: String
        get() {
            val digest = MessageDigest.getInstance("SHA-256").digest(publicKeyRaw)
            val hex = digest.copyOf(8).joinToString("") { "%02X".format(Locale.ROOT, it) }
            return hex.chunked(4).joinToString(" ")
        }

    /** DER signature (`SHA256withECDSA`) over the UTF-8 bytes of [message], base64. */
    fun signBase64(message: String): String {
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(privateKey)
        signer.update(message.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(signer.sign())
    }

    /** The string a [KeyStore] stores. */
    fun encode(): String = buildJsonObject {
        put("private", Base64.getEncoder().encodeToString(privateKey.encoded))
        put("public", publicKeyBase64)
    }.toString()

    companion object {
        fun generate(random: SecureRandom = SecureRandom()): ClientIdentity {
            val generator = KeyPairGenerator.getInstance("EC")
            generator.initialize(ECGenParameterSpec("secp256r1"), random)
            val pair = generator.generateKeyPair()
            val point = (pair.public as ECPublicKey).w
            val raw = ByteArray(64)
            copyFixed(point.affineX.toByteArray(), raw, 0)
            copyFixed(point.affineY.toByteArray(), raw, 32)
            return ClientIdentity(pair.private, raw)
        }

        /** Reads what [encode] wrote; null when [stored] is not a readable identity. */
        fun decode(stored: String): ClientIdentity? = try {
            val obj = Json.parseToJsonElement(stored) as JsonObject
            val priv = Base64.getDecoder().decode((obj["private"] as JsonPrimitive).contentOrNull!!)
            val pub = Base64.getDecoder().decode((obj["public"] as JsonPrimitive).contentOrNull!!)
            val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(priv))
            ClientIdentity(key, pub)
        } catch (e: Exception) {
            null
        }

        /**
         * The stored identity, or a new one written to [store] when there is none or it is
         * unreadable (a new key means the user approves the app again).
         */
        fun loadOrCreate(store: KeyStore, logger: MeshLogger = MeshLogger.NONE): ClientIdentity {
            store.load()?.let { stored ->
                decode(stored)?.let { return it }
                logger.warn(TAG, "stored identity unreadable, generating a new one")
            }
            return generate().also { store.save(it.encode()) }
        }

        private fun copyFixed(source: ByteArray, target: ByteArray, offset: Int) {
            val start = if (source.size > 32) source.size - 32 else 0
            val length = source.size - start
            System.arraycopy(source, start, target, offset + 32 - length, length)
        }

        private const val TAG = "MeshCoreLocalApi"
    }
}

/** The pairing rule: which challenge strings this client agrees to sign. */
object Pairing {
    /** The protocol's own prefix. */
    const val PREFIX = "meshcore-local-api-pair-v1:"
    /** What MeshCore Open's first server sends; still accepted. */
    const val LEGACY_PREFIX = "meshcore-open-pair-v1:"

    val NONCE_SHAPE = Regex("^[A-Za-z0-9_-]{16,128}={0,2}$")

    /**
     * The exact string to sign for a `pairing.challenge`, or null to refuse it. The challenge's
     * `message` must be one of the two prefixes followed by the challenge's own `nonce`, and the
     * nonce must look like one. Anything else is refused, so whatever listens on the port cannot
     * use this client to sign a string of its choosing.
     */
    fun messageToSign(challenge: JsonObject): String? {
        val nonce = (challenge["nonce"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        if (!NONCE_SHAPE.matches(nonce)) return null
        val message = (challenge["message"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        return message.takeIf { it == PREFIX + nonce || it == LEGACY_PREFIX + nonce }
    }
}
