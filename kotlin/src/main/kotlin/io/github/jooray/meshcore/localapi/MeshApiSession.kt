package io.github.jooray.meshcore.localapi

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import kotlin.math.pow

/**
 * A long-lived link to the Local API for an app that reads and writes one channel's data (plus
 * optional extra channels): it pairs with the key in [keyStore], subscribes with the `since`
 * cursor from [cursorStore] and drops replayed duplicates, follows the radio coming and going
 * (`device` pushes), asks once with `channels.join` when the channel is missing, and reconnects
 * with backoff. Create one per app and keep it; [start] and [stop] as the feature is switched.
 *
 * Threading: [scope] runs the connection loop and the reader; give it a background dispatcher
 * (`Dispatchers.IO` or `Default`) and a `SupervisorJob`. [datagrams] is emitted from the reader
 * and suspends when its buffer is full, so a slow collector slows the link instead of losing
 * frames. Everything else is safe to call from any thread.
 */
class MeshApiSession(
    private val config: Config,
    private val keyStore: KeyStore,
    private val scope: CoroutineScope,
    private val cursorStore: CursorStore? = null,
    private val logger: MeshLogger = MeshLogger.NONE,
    http: OkHttpClient? = null,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    data class Config(
        val clientName: String,
        val clientVersion: String,
        /** The main channel; the session state follows its subscription. */
        val channel: String,
        /** `dataType`s read on [channel]; the first is the default for [sendData]. */
        val dataTypes: List<Int>,
        /** Further channels and their data types, subscribed best effort after the main one. */
        val extraChannels: Map<String, List<Int>> = emptyMap(),
        val url: String = MeshCoreApiClient.DEFAULT_URL,
        /** Ask the user to add a missing main channel (`channels.join`), once per connection. */
        val joinChannel: Boolean = true,
        /** The same for [extraChannels]. */
        val joinExtraChannels: Boolean = true,
        /** Also deliver this app's own sends (`outgoing: true`) on [datagrams]. */
        val includeOutgoing: Boolean = false,
        val timeouts: Timeouts = Timeouts(),
        val backoff: Backoff = Backoff(),
        /** For servers that never push `device`: retry a failed subscription after this long. */
        val retryMs: Long = 60_000L,
        val deniedPauseMs: Long = SessionLogic.DENIED_PAUSE_MS,
    ) {
        init {
            require(dataTypes.isNotEmpty()) { "dataTypes must not be empty" }
        }
    }

    /** Waits between connection attempts. */
    data class Backoff(
        val initialMs: Long = 5_000L,
        val maxMs: Long = 60_000L,
        val factor: Double = 2.0,
        /** After the server refused this app (4003): the user has to act, so ask rarely. */
        val refusedMs: Long = 120_000L,
    ) {
        fun delayFor(attempt: Int): Long =
            (initialMs * factor.pow(attempt.coerceIn(0, 16))).toLong().coerceAtMost(maxMs)
    }

    private val http: OkHttpClient = http ?: MeshCoreApiClient.httpClient(config.timeouts)
    private val logic = SessionLogic(config.channel, config.deniedPauseMs, config.joinChannel, clock)
    private val guard = ReplayGuard(cursorStore)
    private val identity: ClientIdentity by lazy { ClientIdentity.loadOrCreate(keyStore, logger) }

    private val _state = MutableStateFlow<SessionState>(SessionState.Disconnected)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val _connected = MutableStateFlow(false)
    /** True while [state] is [SessionState.Connected]. */
    val connected: StateFlow<Boolean> = _connected.asStateFlow()

    private val _datagrams = MutableSharedFlow<MeshEvent.ChannelData>(extraBufferCapacity = 256)
    /** Channel data of the configured channels and types, oldest first, without replayed duplicates. */
    val datagrams: SharedFlow<MeshEvent.ChannelData> = _datagrams.asSharedFlow()

    private val _events = MutableSharedFlow<ApiEvent>(extraBufferCapacity = 256)
    /** Every event of every subscription of this session (channel data deduplicated, own sends included). */
    val events: SharedFlow<ApiEvent> = _events.asSharedFlow()

    private val _device = MutableStateFlow<DeviceUpdate?>(null)
    /** The radio as the server last reported it. */
    val device: StateFlow<DeviceUpdate?> = _device.asStateFlow()

    /** The connection in use, null between connections. */
    @Volatile var client: MeshCoreApiClient? = null
        private set

    val hello: Hello? get() = client?.hello
    /** `hello.capabilities` of the current connection; empty while there is none. */
    val capabilities: Set<String> get() = client?.capabilities ?: emptySet()
    val limits: Limits? get() = client?.limits

    /** The server takes `path`: zero-hop and direct sends are possible. */
    val canSendPath: Boolean get() = _state.value is SessionState.Connected && Capabilities.TX_PATH_DATA in capabilities

    /** When the server last sent anything (wall clock ms); 0 before. For watchdogs. */
    val lastActivityMs: Long get() = client?.lastActivityMs ?: lastActivity
    @Volatile private var lastActivity = 0L

    /** What the server's approval dialog shows for this app. Loads or creates the key. */
    val fingerprint: String get() = identity.fingerprint

    @Volatile private var running = false
    @Volatile private var connectionSince: String? = null
    private var loop: Job? = null
    @Volatile private var retry: Job? = null
    private val extrasLock = Mutex()
    private val extrasSubscribed = HashSet<String>()
    private val extrasJoinAsked = HashSet<String>()

    @Synchronized
    fun start() {
        if (running) return
        running = true
        loop = scope.launch { connectLoop() }
    }

    @Synchronized
    fun stop() {
        running = false
        loop?.cancel()
        loop = null
        retry?.cancel()
        retry = null
        client?.close(CloseCodes.NORMAL, "app stopping")
        client = null
        setState(SessionState.Disconnected)
    }

    /** Drops the connection and starts a fresh one (e.g. from a watchdog). */
    fun restart() {
        stop()
        start()
    }

    /**
     * Sends one datagram. A [route] other than [Route.Flood] goes out only when the server has
     * [Capabilities.TX_PATH_DATA]; otherwise nothing is sent (`unsupported`), so a zero-hop send
     * never turns into a flood. A refused [region] shows in [SessionState.Connected.unknownRegion]
     * until a send goes through.
     */
    suspend fun sendData(
        payload: ByteArray,
        dataType: Int = config.dataTypes.first(),
        channel: String = config.channel,
        region: String? = null,
        route: Route = Route.Flood,
    ): ApiResult<Unit> {
        val c = client ?: return ApiResult.Failed(ApiError(ErrorCodes.DISCONNECTED))
        // Checked here too so that a refused route does not touch the region state.
        if (route != Route.Flood && !c.has(Capabilities.TX_PATH_DATA)) {
            return ApiResult.Failed(ApiError(ErrorCodes.UNSUPPORTED, "server lacks ${Capabilities.TX_PATH_DATA}"))
        }
        val scoped = region?.trim()?.takeIf { it.isNotEmpty() && route != Route.ZeroHop }
        val answer = c.sendData(channel, dataType, payload, scoped, route)
        if (answer.errorCode != ErrorCodes.DISCONNECTED) {
            logic.onSendAnswer(answer, scoped)
            if (c === client && running && _state.value is SessionState.Connected) setState(logic.state)
        }
        if (!answer.isOk) logger.warn(TAG, "send refused: ${answer.errorCode}")
        return answer
    }

    /** `channels.join` on the current connection (long timeout). */
    suspend fun joinChannel(name: String): ApiResult<JoinResult> =
        client?.joinChannel(name) ?: ApiResult.Failed(ApiError(ErrorCodes.DISCONNECTED))

    /** Any request on the current connection. */
    suspend fun request(method: String, params: JsonObject = JsonObject(emptyMap())): ApiResponse =
        client?.request(method, params) ?: ApiResponse.NotConnected

    private suspend fun connectLoop() {
        var attempts = 0
        while (running) {
            val c = MeshCoreApiClient(
                identity, config.clientName, config.clientVersion, scope, config.url, logger, config.timeouts, http,
            )
            logic.connectionStarted()
            // One cursor for every subscription of this connection: a replay that moves the cursor
            // must not make a later subscription skip frames it has not replayed yet.
            connectionSince = guard.since()
            synchronized(extrasSubscribed) {
                extrasSubscribed.clear()
                extrasJoinAsked.clear()
            }
            c.onAwaitingApproval = { if (client === c) setState(SessionState.WaitingForApproval) }
            c.onHello = { hello ->
                attempts = 0
                _device.value = DeviceUpdate(hello.device, null)
                perform(logic.onHello(hello.device), c)
            }
            c.onDevicePush = { update ->
                _device.value = update
                perform(logic.onDevice(update), c)
                if (update.connected && logic.isSubscribed && config.extraChannels.isNotEmpty()) {
                    scope.launch { subscribeExtras(c, update) }
                }
            }
            c.onEvent = { handleEvent(it) }
            client = c
            setState(SessionState.Connecting)
            var refused = false
            try {
                c.connect()
                refused = c.awaitClosed().refused
                if (client === c && running) setState(SessionState.Disconnected)
            } catch (e: CancellationException) {
                c.close(CloseCodes.NORMAL, "app stopping")
                throw e
            } catch (e: MeshApiException) {
                refused = e is MeshApiException.Refused
                logger.warn(TAG, "connection failed: ${e.message}")
                if (!refused && running) setState(SessionState.Failed(e.message ?: "connection failed"))
            } finally {
                lastActivity = c.lastActivityMs
                if (client === c) {
                    retry?.cancel()
                    retry = null
                    client = null
                }
            }
            if (!running) break
            val wait = if (refused) {
                setState(SessionState.NotApproved)
                config.backoff.refusedMs
            } else {
                config.backoff.delayFor(attempts++)
            }
            delay(wait)
        }
    }

    /** Carries out what [logic] decided, then publishes its state. */
    private fun perform(action: SessionLogic.Action, c: MeshCoreApiClient) {
        if (c !== client || !running) return
        when (action) {
            SessionLogic.Action.Subscribe -> scope.launch { subscribeMain(c) }
            SessionLogic.Action.Join -> scope.launch { joinMain(c) }
            SessionLogic.Action.None -> Unit
        }
        setState(logic.state)
        if (logic.retryDue()) scheduleRetry(c)
    }

    private fun scheduleRetry(c: MeshCoreApiClient) {
        retry?.cancel()
        retry = scope.launch {
            delay(config.retryMs)
            if (c !== client || !logic.retryDue()) return@launch
            val info = c.deviceInfo()
            if (c !== client) return@launch
            info.valueOrNull?.let { _device.value = it }
            perform(logic.onRetry(info), c)
        }
    }

    private suspend fun subscribeMain(c: MeshCoreApiClient) {
        val answer = c.subscribe(EventFilter.channelData(config.channel, config.dataTypes, connectionSince))
        if (c !== client) return
        if (!answer.isOk) logger.warn(TAG, "subscribe failed: ${answer.errorCode}")
        perform(logic.onSubscribeAnswer(answer), c)
        if (answer.isOk) subscribeExtras(c, null)
    }

    private suspend fun joinMain(c: MeshCoreApiClient) {
        val answer = c.joinChannel(config.channel)
        if (c !== client) return
        if (!answer.isOk) logger.warn(TAG, "channels.join failed: ${answer.errorCode}")
        perform(logic.onJoinAnswer(answer), c)
    }

    /**
     * Best effort, one run at a time: each extra channel not yet subscribed on this connection is
     * subscribed; a missing one is asked for once per connection. With a [push], only channels it
     * lists are tried (the radio's channel list changed).
     */
    private suspend fun subscribeExtras(c: MeshCoreApiClient, push: DeviceUpdate?) = extrasLock.withLock {
        for ((name, types) in config.extraChannels) {
            if (c !== client || !running) return@withLock
            if (synchronized(extrasSubscribed) { name in extrasSubscribed }) continue
            if (push != null && !push.hasChannel(name)) continue
            val filter = EventFilter.channelData(name, types, connectionSince)
            var answer = c.subscribe(filter)
            val ask = answer.errorCode == ErrorCodes.UNKNOWN_CHANNEL && config.joinExtraChannels &&
                logic.isRadioConnected && synchronized(extrasSubscribed) { extrasJoinAsked.add(name) }
            if (ask && c.joinChannel(name).isOk) answer = c.subscribe(filter)
            if (answer.isOk) {
                synchronized(extrasSubscribed) { extrasSubscribed.add(name) }
            } else {
                logger.warn(TAG, "no subscription for an extra channel: ${answer.errorCode}")
            }
        }
    }

    private suspend fun handleEvent(e: ApiEvent) {
        val d = e.event as? MeshEvent.ChannelData
        if (d == null) {
            _events.emit(e)
            return
        }
        if (d.outgoing) {
            _events.emit(e)
            if (config.includeOutgoing && wanted(d)) _datagrams.emit(d)
            return
        }
        if (!guard.accept(d)) return
        _events.emit(e)
        if (wanted(d)) _datagrams.emit(d)
        guard.advance(d)
    }

    private fun wanted(d: MeshEvent.ChannelData): Boolean {
        val types = if (d.channel == config.channel) config.dataTypes else config.extraChannels[d.channel]
        return types != null && d.dataType in types
    }

    private fun setState(value: SessionState) {
        if (value::class != _state.value::class) logger.info(TAG, "state ${value::class.simpleName}")
        _state.value = value
        _connected.value = value is SessionState.Connected
    }

    private companion object {
        const val TAG = "MeshCoreLocalApi"
    }
}
