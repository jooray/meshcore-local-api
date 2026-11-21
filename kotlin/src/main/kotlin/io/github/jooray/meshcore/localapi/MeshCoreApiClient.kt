package io.github.jooray.meshcore.localapi

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** How long the client waits for what. */
data class Timeouts(
    /** TCP connect, the HTTP upgrade and writes. Also bounds a server that accepts and never answers. */
    val socketMs: Long = 15_000L,
    /** WebSocket pings; a dead link is noticed after one missed pong. */
    val pingMs: Long = 20_000L,
    /** From connecting to `hello`, including the user answering the approval dialog (2 min). */
    val handshakeMs: Long = 150_000L,
    /** A normal request. */
    val requestMs: Long = 15_000L,
    /** `channels.join`: the server's dialog stays up to two minutes. */
    val joinMs: Long = 150_000L,
) {
    fun forMethod(method: String): Long = if (method == "channels.join") joinMs else requestMs
}

/** Why [MeshCoreApiClient.connect] did not reach `hello`. */
sealed class MeshApiException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The server refused this key or signature, the user denied it, or the app was revoked (4003). */
    class Refused(val closeCode: Int?, val error: ApiError?) :
        MeshApiException("refused: ${error?.code ?: closeCode}")

    /** The server turned the connection away for now: `pairing_pending`, `rate_limited`, `too_many_clients`. */
    class Rejected(val closeCode: Int?, val error: ApiError?) :
        MeshApiException("rejected: ${error?.code ?: closeCode}")

    /** The `pairing.challenge` was not one this client signs; the connection was closed. */
    class BadChallenge : MeshApiException("pairing challenge refused")

    class HandshakeTimeout : MeshApiException("no hello in time")

    /** The socket failed or closed before `hello`. */
    class Closed(val closeCode: Int?, val reason: String?, cause: Throwable? = null) :
        MeshApiException("closed before hello: ${cause?.message ?: closeCode}", cause)
}

/** One connection's life. */
sealed interface ConnectionState {
    data object Idle : ConnectionState
    data object Connecting : ConnectionState
    /** The challenge is signed; the user may have to approve the app on the server. */
    data object AwaitingApproval : ConnectionState
    data class Ready(val hello: Hello) : ConnectionState
    data class Closed(
        val code: Int?,
        val reason: String?,
        /** The last error frame before pairing completed, if any. */
        val error: ApiError? = null,
        val cause: Throwable? = null,
    ) : ConnectionState {
        /** The server refused this app; retry slowly, the user has to act. */
        val refused: Boolean get() = code == CloseCodes.REFUSED || error?.code == ErrorCodes.UNAUTHORIZED
    }
}

/**
 * One connection to a MeshCore Local API server: handshake, pairing, requests and events.
 * An instance is used once: [connect], use it, and when [state] is [ConnectionState.Closed] make a
 * new one ([MeshApiSession] does that, with backoff).
 *
 * Threading: OkHttp delivers frames on its own thread into a bounded inbox; one coroutine in
 * [scope] reads them in arrival order, so replayed frames keep their order. [events] is emitted
 * from that coroutine and suspends when the buffer is full, slowing the reader rather than
 * dropping data. All public functions are safe to call from any thread.
 */
class MeshCoreApiClient(
    private val identity: ClientIdentity,
    private val clientName: String,
    private val clientVersion: String,
    private val scope: CoroutineScope,
    val url: String = DEFAULT_URL,
    private val logger: MeshLogger = MeshLogger.NONE,
    private val timeouts: Timeouts = Timeouts(),
    private val http: OkHttpClient = httpClient(timeouts),
) {
    init {
        require(clientName.length in 1..64) { "client name must be 1-64 characters" }
        require(clientVersion.length <= 32) { "client version must be at most 32 characters" }
    }

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private val _state = MutableStateFlow<ConnectionState>(ConnectionState.Idle)
    val state: StateFlow<ConnectionState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<ApiEvent>(extraBufferCapacity = 256)
    /** Every event of every subscription, in arrival order. Unknown event types are left out. */
    val events: SharedFlow<ApiEvent> = _events.asSharedFlow()

    private val _device = MutableStateFlow<DeviceUpdate?>(null)
    /** The radio as last reported: from `hello` (channels null), then every `device` push. */
    val device: StateFlow<DeviceUpdate?> = _device.asStateFlow()

    /** The server's `hello`, null before the handshake completes. */
    val hello: Hello? get() = (_state.value as? ConnectionState.Ready)?.hello ?: readyHello
    val capabilities: Set<String> get() = hello?.capabilities ?: emptySet()
    val limits: Limits? get() = hello?.limits
    fun has(capability: String): Boolean = capability in capabilities

    /** When the server last sent a frame (wall clock ms); 0 before the first. For watchdogs. */
    @Volatile var lastActivityMs: Long = 0L
        private set

    /** Called on the reader when the challenge is signed and the server may be asking the user. */
    internal var onAwaitingApproval: (() -> Unit)? = null
    /** Called in order on the reader with `hello`, before any later frame is read. */
    internal var onHello: ((Hello) -> Unit)? = null
    /** Called in order on the reader for each `device` push, before [device] updates. */
    internal var onDevicePush: ((DeviceUpdate) -> Unit)? = null
    /** Called in order on the reader for each event, before it goes to [events]. */
    internal var onEvent: (suspend (ApiEvent) -> Unit)? = null

    private val started = AtomicBoolean(false)
    private val requestIds = AtomicLong(0)
    private val pending = ConcurrentHashMap<Long, CompletableDeferred<ApiResponse>>()
    private val helloResult = CompletableDeferred<Hello>()
    private val closed = CompletableDeferred<ConnectionState.Closed>()
    @Volatile private var socket: WebSocket? = null
    @Volatile private var readyHello: Hello? = null
    @Volatile private var closeCode: Int? = null
    @Volatile private var closeReason: String? = null
    @Volatile private var failure: Throwable? = null
    @Volatile private var lastError: ApiError? = null
    @Volatile private var badChallenge = false
    private var reader: Job? = null

    /**
     * Opens the socket, pairs and waits for `hello`. Throws [MeshApiException] when that fails;
     * the client is then closed. Call once per instance.
     */
    suspend fun connect(): Hello {
        check(started.compareAndSet(false, true)) { "MeshCoreApiClient is single use; make a new one" }
        _state.value = ConnectionState.Connecting
        val inbox = Channel<String>(INBOX_CAPACITY)
        val ws = http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                webSocket.send(helloFrame())
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                if (inbox.trySend(text).isFailure) {
                    // The API sends far less than this; a reader this far behind is broken.
                    logger.warn(TAG, "inbox full, closing")
                    webSocket.close(1008, "client overloaded")
                }
            }

            override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                closeCode = code
                closeReason = reason
                webSocket.close(CloseCodes.NORMAL, null)
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (closeCode == null) {
                    closeCode = code
                    closeReason = reason
                }
                inbox.close()
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                logger.warn(TAG, "socket failure: ${t.message}")
                failure = t
                inbox.close()
            }
        })
        socket = ws
        reader = scope.launch { readLoop(ws, inbox) }
        try {
            return withTimeoutOrNull(timeouts.handshakeMs) { helloResult.await() }
                ?: run {
                    close(CloseCodes.HANDSHAKE, "hello timeout")
                    throw MeshApiException.HandshakeTimeout()
                }
        } catch (e: CancellationException) {
            ws.cancel()
            throw e
        }
    }

    /** Waits until the connection has ended and says how. */
    suspend fun awaitClosed(): ConnectionState.Closed = closed.await()

    /** Closes the connection; pending requests answer [ApiResponse.NotConnected]. */
    fun close(code: Int = CloseCodes.NORMAL, reason: String = "client closing") {
        val ws = socket ?: return
        if (!ws.close(code, reason)) ws.cancel()
        // A server that never answers the close frame would keep the reader waiting.
        scope.launch {
            kotlinx.coroutines.delay(CLOSE_GRACE_MS)
            ws.cancel()
        }
    }

    /**
     * Sends one request and waits for its answer. [timeoutMs] defaults to [Timeouts.forMethod]
     * (long for `channels.join`). Only after `hello`; before that the answer is
     * [ApiResponse.NotConnected]. A method or parameter whose capability the server does not list
     * ([missingCapability]) is not sent: the answer is `unsupported` with
     * [ApiError.missingCapability] set.
     */
    suspend fun request(
        method: String,
        params: JsonObject = JsonObject(emptyMap()),
        timeoutMs: Long = timeouts.forMethod(method),
    ): ApiResponse {
        val ws = socket ?: return ApiResponse.NotConnected
        if (_state.value !is ConnectionState.Ready) return ApiResponse.NotConnected
        missingCapability(method, params, capabilities)?.let {
            return ApiResponse.Error(ApiError.missingCapability(it))
        }
        val id = requestIds.incrementAndGet()
        val answer = CompletableDeferred<ApiResponse>()
        pending[id] = answer
        try {
            val frame = buildJsonObject {
                put("id", id)
                put("method", method)
                put("params", params)
            }.toString()
            if (!ws.send(frame)) return ApiResponse.NotConnected
            return withTimeoutOrNull(timeoutMs) { answer.await() } ?: ApiResponse.Timeout
        } finally {
            pending.remove(id)
        }
    }

    // Typed requests.

    suspend fun deviceInfo(): ApiResult<DeviceUpdate> = request("device.info").toResult { r ->
        DeviceUpdate(DeviceInfo.parse(r), ChannelInfo.parseList(r["channels"]))
    }

    suspend fun channelsList(): ApiResult<List<ChannelInfo>> =
        request("channels.list").toResult { ChannelInfo.parseList(it["channels"]) ?: emptyList() }

    /** `events.subscribe`; the value is the subscription id. */
    suspend fun subscribe(filter: EventFilter): ApiResult<String> =
        request("events.subscribe", filter.toParams()).toResult { it.string("subscriptionId") ?: "" }

    suspend fun unsubscribe(subscriptionId: String): ApiResult<Unit> =
        request("events.unsubscribe", buildJsonObject { put("subscriptionId", subscriptionId) }).toResult { }

    /**
     * `channel.sendData`. A [route] other than [Route.Flood] needs [Capabilities.TX_PATH_DATA]
     * and a [region] needs [Capabilities.REGIONS]; without them nothing is sent and the answer is
     * `unsupported` (a server without `tx_path_data` would ignore `path` and flood). An invalid
     * [Route.Direct] path is `bad_request`, also without sending. An empty [region] means the
     * channel's own scope.
     */
    suspend fun sendData(
        channel: String,
        dataType: Int,
        payload: ByteArray,
        region: String? = null,
        route: Route = Route.Flood,
    ): ApiResult<Unit> {
        if (route is Route.Direct && !route.valid) {
            return ApiResult.Failed(ApiError(ErrorCodes.BAD_REQUEST, "invalid path"))
        }
        return request("channel.sendData", sendDataParams(channel, dataType, payload, region, route)).toResult { }
    }

    suspend fun sendText(channel: String, text: String, region: String? = null): ApiResult<Unit> =
        request("channel.sendText", buildJsonObject {
            put("channel", channel)
            put("text", text)
            region?.takeIf { it.isNotEmpty() }?.let { put("region", it) }
        }).toResult { }

    suspend fun sendDirectText(pubkey: String, text: String): ApiResult<Unit> =
        request("direct.sendText", buildJsonObject {
            put("pubkey", pubkey)
            put("text", text)
        }).toResult { }

    /** `contacts.list` (capability `contacts`); [limit] 1..500, server default 200. */
    suspend fun contactsList(limit: Int? = null): ApiResult<List<Contact>> =
        request("contacts.list", buildJsonObject { limit?.let { put("limit", it) } }).toResult { r ->
            (r["contacts"] as? kotlinx.serialization.json.JsonArray)?.mapNotNull { e ->
                val o = e as? JsonObject ?: return@mapNotNull null
                o.string("pubkey")?.let { Contact(it, o.string("name"), o.int("type"), o.anyString("lastSeen")) }
            } ?: emptyList()
        }

    /** `advert.send` (capability `advert_send`); [flood] false is a zero-hop advert. */
    suspend fun advertSend(flood: Boolean = true): ApiResult<Unit> =
        request("advert.send", buildJsonObject { put("flood", flood) }).toResult { }

    /** `channels.join` for a hashtag channel; waits [Timeouts.joinMs] for the user's answer. */
    suspend fun joinChannel(name: String): ApiResult<JoinResult> =
        request("channels.join", buildJsonObject { put("name", name) }).toResult { r ->
            JoinResult(r.int("index"), r.string("name") ?: name, r.bool("created") == true)
        }

    /** `regions.resolve`: the region name for a point, null name when none contains it. */
    suspend fun resolveRegion(lat: Double, lon: Double): ApiResult<ResolvedRegion> =
        request("regions.resolve", buildJsonObject {
            put("lat", lat)
            put("lon", lon)
        }).toResult { r ->
            val region = r["region"] as? JsonObject
            ResolvedRegion(region?.string("name")?.takeIf { it.isNotBlank() && it.length <= 64 }, region?.double("distanceKm"))
        }

    /** `radio.stats` (capability `radio_stats`); [RadioStats.preset] is the LoRa preset. */
    suspend fun radioStats(): ApiResult<RadioStats> = request("radio.stats").toResult { r ->
        RadioStats(RadioParams.parse(r["preset"] as? JsonObject), r)
    }

    private suspend fun readLoop(ws: WebSocket, inbox: Channel<String>) {
        var signed = false
        try {
            for (text in inbox) {
                lastActivityMs = System.currentTimeMillis()
                val message = try {
                    json.parseToJsonElement(text) as? JsonObject
                } catch (e: Exception) {
                    null
                }
                if (message == null) {
                    logger.warn(TAG, "server sent invalid JSON")
                    continue
                }
                when (message.string("type")) {
                    "pairing.challenge" -> {
                        if (signed) continue
                        signed = true
                        val toSign = Pairing.messageToSign(message)
                        if (toSign == null) {
                            logger.warn(TAG, "pairing challenge refused: message is not the pairing string for its nonce")
                            badChallenge = true
                            ws.close(1002, "bad challenge")
                            break
                        }
                        _state.value = ConnectionState.AwaitingApproval
                        onAwaitingApproval?.invoke()
                        ws.send(buildJsonObject {
                            put("type", "pair")
                            put("signature", identity.signBase64(toSign))
                        }.toString())
                    }

                    "hello" -> {
                        val hello = Hello.parse(message)
                        readyHello = hello
                        _device.value = DeviceUpdate(hello.device, null)
                        _state.value = ConnectionState.Ready(hello)
                        onHello?.invoke(hello)
                        helloResult.complete(hello)
                    }

                    "device" -> {
                        val update = DeviceUpdate.parse(message)
                        onDevicePush?.invoke(update)
                        _device.value = update
                    }

                    "event" -> {
                        val event = (message["event"] as? JsonObject)?.let { MeshEvent.parse(it) } ?: continue
                        val apiEvent = ApiEvent(message.string("subscriptionId"), event)
                        onEvent?.invoke(apiEvent)
                        _events.emit(apiEvent)
                    }

                    "error" -> {
                        val error = ApiResponse.parse(message) as? ApiResponse.Error
                        if (error != null && message["id"] == null) {
                            lastError = error.error
                            logger.warn(TAG, "server error ${error.error.code}")
                        }
                    }
                }
                val id = (message["id"] as? JsonPrimitive)?.content?.toLongOrNull()
                if (id != null && message.containsKey("ok")) {
                    pending.remove(id)?.complete(ApiResponse.parse(message))
                }
            }
        } finally {
            ws.cancel()
            socket = null
            pending.values.forEach { it.complete(ApiResponse.NotConnected) }
            pending.clear()
            val end = ConnectionState.Closed(closeCode, closeReason, lastError, failure)
            _state.value = end
            closed.complete(end)
            if (!helloResult.isCompleted) helloResult.completeExceptionally(handshakeFailure(end))
        }
    }

    private fun handshakeFailure(end: ConnectionState.Closed): MeshApiException = when {
        badChallenge -> MeshApiException.BadChallenge()
        end.refused -> MeshApiException.Refused(end.code, end.error)
        end.error != null -> MeshApiException.Rejected(end.code, end.error)
        else -> MeshApiException.Closed(end.code, end.reason, end.cause)
    }

    private fun helloFrame(): String = buildJsonObject {
        put("type", "hello")
        putJsonObject("client") {
            put("name", clientName)
            put("version", clientVersion)
            put("publicKey", identity.publicKeyBase64)
        }
    }.toString()

    companion object {
        const val DEFAULT_URL = "ws://127.0.0.1:8787/api/v1"
        private const val TAG = "MeshCoreLocalApi"
        private const val INBOX_CAPACITY = 1024
        private const val CLOSE_GRACE_MS = 5_000L

        /**
         * The OkHttp client this library uses by default. The read timeout bounds only the HTTP
         * upgrade (OkHttp clears it once the socket is a WebSocket; the pings watch the link
         * after that). Without it, a frozen server whose kernel socket still accepts connections
         * leaves the upgrade waiting forever and the client never retries.
         */
        fun httpClient(timeouts: Timeouts = Timeouts()): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(timeouts.socketMs, TimeUnit.MILLISECONDS)
            .readTimeout(timeouts.socketMs, TimeUnit.MILLISECONDS)
            .writeTimeout(timeouts.socketMs, TimeUnit.MILLISECONDS)
            .pingInterval(timeouts.pingMs, TimeUnit.MILLISECONDS)
            .build()

        private val METHOD_CAPABILITY = mapOf(
            "contacts.list" to Capabilities.CONTACTS,
            "direct.sendText" to Capabilities.CONTACTS,
            "advert.send" to Capabilities.ADVERT_SEND,
            "regions.list" to Capabilities.REGIONS,
            "regions.resolve" to Capabilities.REGIONS,
            "channels.join" to Capabilities.CHANNELS_JOIN,
            "radio.stats" to Capabilities.RADIO_STATS,
        )

        /**
         * The capability a request needs and the server lacks ([capabilities] from `hello`), or
         * null when it may be sent. Covers the methods of SPEC.md section 8 and the parameters
         * that change what goes on the air or what is requested: `region` (regions), `path` /
         * `pathHashSize` (tx_path_data, tx_path_text), `since` (replay), `pubkeys` and the event
         * types `direct.text` / `advert` (contacts). Core methods need nothing.
         */
        fun missingCapability(method: String, params: JsonObject, capabilities: Set<String>): String? {
            fun need(name: String) = name.takeIf { it !in capabilities }
            METHOD_CAPABILITY[method]?.let { need(it)?.let { m -> return m } }
            fun has(key: String) = params[key].let { it != null && it !is kotlinx.serialization.json.JsonNull }
            when (method) {
                "channel.sendData", "channel.sendText" -> {
                    if (has("region")) need(Capabilities.REGIONS)?.let { return it }
                    if (has("path") || has("pathHashSize")) {
                        val cap = if (method == "channel.sendData") Capabilities.TX_PATH_DATA else Capabilities.TX_PATH_TEXT
                        need(cap)?.let { return it }
                    }
                }
                "events.subscribe" -> {
                    if (has("since")) need(Capabilities.REPLAY)?.let { return it }
                    if (has("pubkeys")) need(Capabilities.CONTACTS)?.let { return it }
                    val types = params.strings("events")
                    if ("direct.text" in types || "advert" in types) need(Capabilities.CONTACTS)?.let { return it }
                }
            }
            return null
        }

        /**
         * `channel.sendData` params. [Route.ZeroHop] is `"path": ""` with `pathHashSize` 1 and no
         * region (a flood scope does not apply to it, and an unknown name would only make the
         * server refuse a packet it would not scope anyway). [Route.Direct] carries the hex path,
         * its hash size and the region when given.
         */
        fun sendDataParams(channel: String, dataType: Int, payload: ByteArray, region: String?, route: Route): JsonObject =
            buildJsonObject {
                put("channel", channel)
                put("dataType", dataType)
                put("payload", Base64.getEncoder().encodeToString(payload))
                val scope = region?.trim()?.takeIf { it.isNotEmpty() }
                when (route) {
                    Route.Flood -> scope?.let { put("region", it) }
                    Route.ZeroHop -> {
                        put("path", "")
                        put("pathHashSize", 1)
                    }
                    is Route.Direct -> {
                        scope?.let { put("region", it) }
                        put("path", route.path.toHex())
                        put("pathHashSize", route.hashSize)
                    }
                }
            }
    }
}

data class ResolvedRegion(val name: String?, val distanceKm: Double?)

data class RadioStats(val preset: RadioParams?, val raw: JsonObject)
