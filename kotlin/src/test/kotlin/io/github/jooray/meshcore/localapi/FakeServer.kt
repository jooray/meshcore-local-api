package io.github.jooray.meshcore.localapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.io.Closeable
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * An in-process Local API server, enough of LOCAL_API.md for the client: pairing with a real
 * signature check, `hello`, the main methods, `device` pushes, events and `since` replay from a
 * small archive. Tests change its behaviour through the public vars.
 */
class FakeServer : Closeable {
    private val server = MockWebServer()

    /** The challenge's `message` for a nonce; the default is the protocol's own prefix. */
    @Volatile var challengeMessage: (String) -> String? = { Pairing.PREFIX + it }
    /** Close with 4003 after a valid `pair` (the user denied, or the key is revoked). */
    @Volatile var refusePairing = false
    @Volatile var deviceConnected: Boolean? = true
    /** What `hello.capabilities` lists; [BASE] unless a test changes it. */
    @Volatile var capabilities: List<String>? = BASE
    val channels: MutableList<String> = CopyOnWriteArrayList(listOf("#test"))
    /** `channels.join`: null adds the channel, otherwise the error code. */
    @Volatile var joinError: String? = null
    /** Archived `channel.data` events replayed on `since`. */
    val archive: MutableList<JsonObject> = CopyOnWriteArrayList()
    /** Override for a method: return a full response frame, or null to stay silent. */
    @Volatile var handler: ((Conn, String, JsonObject) -> JsonObject?)? = null

    val requests = LinkedBlockingQueue<JsonObject>()
    val connections = LinkedBlockingQueue<Conn>()
    val pairs = LinkedBlockingQueue<JsonObject>()
    val connectionCount = AtomicInteger()
    private val subscriptionIds = AtomicInteger()

    val url: String get() = server.url("/api/v1").toString().replaceFirst("http", "ws")

    init {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                connectionCount.incrementAndGet()
                return MockResponse().withWebSocketUpgrade(Conn().also { all.add(it) })
            }
        }
        server.start()
    }

    private val all: MutableList<Conn> = CopyOnWriteArrayList()

    override fun close() {
        all.forEach { c -> runCatching { c.ws.cancel() } }
        try {
            server.shutdown()
        } catch (e: java.io.IOException) {
            // MockWebServer waits for upgraded sockets; they are cancelled above.
        }
    }

    /** Takes the next method request, failing after [seconds]. */
    fun nextRequest(method: String, seconds: Long = 5): JsonObject {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        while (true) {
            val left = deadline - System.nanoTime()
            val r = requests.poll(left.coerceAtLeast(0), TimeUnit.NANOSECONDS)
                ?: throw AssertionError("no $method request")
            if (r.string("method") == method) return r
        }
    }

    fun nextConnection(seconds: Long = 5): Conn =
        connections.poll(seconds, TimeUnit.SECONDS) ?: throw AssertionError("no connection")

    inner class Conn : WebSocketListener() {
        @Volatile lateinit var ws: WebSocket
        @Volatile private var publicKey: ByteArray? = null
        @Volatile private var expected: String? = null
        @Volatile var paired = false
        val subscriptions: MutableList<Pair<String, JsonObject>> = CopyOnWriteArrayList()

        override fun onOpen(webSocket: WebSocket, response: Response) {
            ws = webSocket
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(code, null)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            ws = webSocket
            val msg = Json.parseToJsonElement(text).jsonObject
            when (msg.string("type")) {
                "hello" -> {
                    val client = msg["client"] as JsonObject
                    publicKey = Base64.getDecoder().decode(client.string("publicKey"))
                    val nonce = "n" + System.nanoTime().toString().padStart(20, '0')
                    expected = Pairing.PREFIX + nonce
                    val message = challengeMessage(nonce)
                    // The server verifies what it put in `message`.
                    expected = message ?: (Pairing.PREFIX + nonce)
                    send(buildJsonObject {
                        put("type", "pairing.challenge")
                        put("protocol", 1)
                        put("nonce", nonce)
                        put("fingerprint", "0000 0000 0000 0000")
                        message?.let { put("message", it) }
                    })
                }
                "pair" -> {
                    pairs.add(msg)
                    if (!verify(publicKey!!, expected!!, msg.string("signature")!!)) {
                        send(buildJsonObject {
                            put("type", "error")
                            put("error", buildJsonObject { put("code", "unauthorized"); put("message", "bad signature") })
                        })
                        webSocket.close(4003, "bad signature")
                        return
                    }
                    if (refusePairing) {
                        send(buildJsonObject {
                            put("type", "error")
                            put("error", buildJsonObject { put("code", "unauthorized"); put("message", "pairing denied") })
                        })
                        webSocket.close(4003, "pairing denied")
                        return
                    }
                    paired = true
                    send(helloFrame())
                    connections.add(this)
                }
                else -> {
                    if (!paired) {
                        webSocket.close(4001, "handshake out of order")
                        return
                    }
                    requests.add(msg)
                    val method = msg.string("method") ?: return
                    val params = msg["params"] as? JsonObject ?: JsonObject(emptyMap())
                    val custom = handler
                    if (custom != null) {
                        custom(this, method, params)?.let { send(withId(it, msg["id"]!!)) }
                        return
                    }
                    // A strict server refuses a feature it does not offer.
                    val caps = capabilities.orEmpty()
                    val unsupported = (method == "channels.join" && "channels_join" !in caps) ||
                        (params.containsKey("region") && "regions" !in caps) ||
                        (params.containsKey("path") && "tx_path_data" !in caps)
                    if (unsupported) {
                        send(error(msg["id"]!!, "unsupported"))
                        return
                    }
                    answer(msg["id"]!!, method, params)
                }
            }
        }

        private fun answer(id: JsonElement, method: String, params: JsonObject) {
            when (method) {
                "events.subscribe" -> {
                    val channel = params.string("channel")
                    if (channel != null && (deviceConnected == false || channel !in channels)) {
                        send(error(id, "unknown_channel"))
                        return
                    }
                    val sid = "s${subscriptionIds.incrementAndGet()}"
                    subscriptions.add(sid to params)
                    send(ok(id, buildJsonObject { put("subscriptionId", sid) }))
                    // A server without `replay` ignores `since`.
                    val since = params.string("since")?.takeIf { "replay" in capabilities.orEmpty() }
                    if (since != null) {
                        val types = params.ints("dataTypes")
                        archive.filter { e ->
                            (channel == null || e.string("channel") == channel) &&
                                (types == null || e.int("dataType") in types) &&
                                e.string("receivedAt")!! >= since
                        }.forEach { event(sid, it) }
                    }
                }
                "channel.sendData" -> send(ok(id, buildJsonObject { put("queued", true) }))
                "channels.join" -> {
                    val err = joinError
                    if (err != null) {
                        send(error(id, err))
                    } else {
                        val name = params.string("name")!!
                        channels.add(name)
                        send(ok(id, buildJsonObject { put("index", 1); put("name", name); put("created", true) }))
                    }
                }
                "device.info" -> send(ok(id, buildJsonObject {
                    put("name", "Test node")
                    deviceConnected?.let { put("connected", it) }
                    put("channels", channelList())
                }))
                else -> send(error(id, "unknown_method"))
            }
        }

        fun send(frame: JsonObject) {
            ws.send(frame.toString())
        }

        fun event(subscriptionId: String?, event: JsonObject) = send(buildJsonObject {
            put("type", "event")
            subscriptionId?.let { put("subscriptionId", it) }
            put("event", event)
        })

        fun pushDevice(connected: Boolean) = send(buildJsonObject {
            put("type", "device")
            put("device", buildJsonObject { put("name", "Test node"); put("connected", connected) })
            put("channels", if (connected) channelList() else buildJsonArray { })
        })

        fun close(code: Int, reason: String) {
            ws.close(code, reason)
        }

        private fun helloFrame() = buildJsonObject {
            put("type", "hello")
            put("protocol", 1)
            put("client", buildJsonObject { put("name", "x"); put("fingerprint", "0000") })
            put("device", buildJsonObject {
                put("name", "Test node")
                put("firmwareVerCode", 11)
                deviceConnected?.let { put("connected", it) }
                put("radio", buildJsonObject { put("sf", 11); put("bwHz", 250000); put("cr", 5); put("freqHz", 869525000) })
            })
            put("eventTypes", buildJsonArray { listOf("channel.text", "channel.data", "direct.text", "advert").forEach { add(JsonPrimitive(it)) } })
            put("limits", buildJsonObject { put("maxPayloadBytes", 163); put("sendsPerMinute", 30); put("maxSubscriptions", 16) })
            capabilities?.let { caps -> put("capabilities", buildJsonArray { caps.forEach { add(JsonPrimitive(it)) } }) }
        }

        private fun channelList() = buildJsonArray {
            channels.forEachIndexed { i, name -> add(buildJsonObject { put("index", i); put("name", name) }) }
        }
    }

    companion object {
        /** Everything but the routed-send and radio extensions. */
        val BASE = listOf("contacts", "advert_send", "regions", "channels_join", "replay", "radio_stats")

        fun ok(id: JsonElement, result: JsonObject) = buildJsonObject {
            put("id", id)
            put("ok", true)
            put("result", result)
        }

        fun error(id: JsonElement, code: String) = buildJsonObject {
            put("id", id)
            put("ok", false)
            put("error", buildJsonObject { put("code", code); put("message", code) })
        }

        fun withId(frame: JsonObject, id: JsonElement) = JsonObject(frame + ("id" to id))

        fun dataEvent(
            channel: String = "#test",
            dataType: Int = 0x0150,
            payload: ByteArray = byteArrayOf(1, 2, 3),
            receivedAt: String = "2026-01-01T10:00:00.000Z",
            outgoing: Boolean = false,
            hops: Int? = 1,
        ) = buildJsonObject {
            put("type", "channel.data")
            put("channel", channel)
            put("channelIndex", 0)
            put("dataType", dataType)
            put("payload", Base64.getEncoder().encodeToString(payload))
            put("snrDb", -7.25)
            put("hops", hops)
            put("receivedAt", receivedAt)
            put("outgoing", outgoing)
        }

        private val p256: ECParameterSpec by lazy {
            AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(ECParameterSpec::class.java)
        }

        fun verify(raw: ByteArray, message: String, signatureB64: String): Boolean {
            val x = BigInteger(1, raw.copyOfRange(0, 32))
            val y = BigInteger(1, raw.copyOfRange(32, 64))
            val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256))
            val v = Signature.getInstance("SHA256withECDSA")
            v.initVerify(key)
            v.update(message.toByteArray(Charsets.UTF_8))
            return try {
                v.verify(Base64.getDecoder().decode(signatureB64))
            } catch (e: Exception) {
                false
            }
        }

        private fun JsonObject.ints(key: String): List<Int>? =
            (this[key] as? kotlinx.serialization.json.JsonArray)?.map { (it as JsonPrimitive).content.toInt() }
    }
}
