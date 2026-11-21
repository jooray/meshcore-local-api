package io.github.jooray.meshcore.localapi

/** What a [MeshApiSession] is doing, for the app's status line. */
sealed interface SessionState {
    /** Not started, or stopped. */
    data object Disconnected : SessionState
    data object Connecting : SessionState
    /** The user has to approve this app on the server (its dialog shows [MeshApiSession.fingerprint]). */
    data object WaitingForApproval : SessionState
    /** The server refused or revoked this app; retried slowly. */
    data object NotApproved : SessionState
    /**
     * Subscribed to the main channel. [unknownRegion] is the flood region the server refused on
     * the last send, if any: receiving works, scoped sending does not until it is fixed.
     */
    data class Connected(val deviceName: String?, val unknownRegion: String? = null) : SessionState
    /** The server runs and this app is paired, but it has no radio connected. */
    data object NoRadio : SessionState
    /** `channels.join` is waiting for the user to answer the server's prompt. */
    data object WaitingForChannel : SessionState
    /** The user declined to add the channel; not asked again for [MeshApiSession.Config.deniedPauseMs]. */
    data object ChannelDenied : SessionState
    /** The radio has no such channel and asking did not add it; [code] is the join error, if any. */
    data class ChannelMissing(val code: String?) : SessionState
    /** `events.subscribe` failed for another reason; [code] is the error code (`timeout` without an answer). */
    data class Refused(val code: String?) : SessionState
    /** The connection failed; the session retries with backoff. */
    data class Failed(val message: String) : SessionState
}

/**
 * The decisions of one session after `hello`, on typed messages and nothing else: no socket, no
 * coroutines. [MeshApiSession] carries them out.
 *
 *  - `hello.device.connected` false, or a `device` push saying so: no radio, keep the socket and
 *    wait for the next push;
 *  - radio connected: subscribe. A `device` push with `connected: true` subscribes again only
 *    when this connection holds no subscription (one survives the radio going away; a second
 *    would deliver every event twice). The initial state comes from `hello.device`;
 *  - `unknown_channel` while the radio is connected: ask once per connection with
 *    `channels.join` (only when the server has `channels_join`), never within [deniedPauseMs]
 *    of a refusal; then subscribe;
 *  - `unknown_channel` while it is not: no radio (without one the server knows no channels);
 *  - any other error: refused, with the code.
 *
 * A server that never sends `device` gets a slow retry instead ([retryDue]). The denial pause
 * outlives connections, not the instance.
 */
internal class SessionLogic(
    private val channelName: String,
    private val deniedPauseMs: Long = DENIED_PAUSE_MS,
    /** False: never send `channels.join`; a missing channel is [SessionState.ChannelMissing]. */
    private val askToJoin: Boolean = true,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    enum class Action { None, Subscribe, Join }

    var state: SessionState = SessionState.Connecting
        @Synchronized get
        private set

    private var authenticated = false
    private var deviceName: String? = null
    private var radioConnected = true
    private var sendsDeviceMessages = false
    private var subscribed = false
    private var busy = false
    private var joinAsked = false
    private var unknownRegion: String? = null
    private var deniedUntil = 0L

    /** A new socket: everything but the denial pause starts over. */
    @Synchronized
    fun connectionStarted() {
        state = SessionState.Connecting
        authenticated = false
        deviceName = null
        radioConnected = true
        sendsDeviceMessages = false
        subscribed = false
        busy = false
        joinAsked = !askToJoin
        unknownRegion = null
    }

    val isSubscribed: Boolean
        @Synchronized get() = subscribed

    val isRadioConnected: Boolean
        @Synchronized get() = authenticated && radioConnected

    @Synchronized
    fun onHello(device: DeviceInfo?, canJoin: Boolean = true): Action {
        authenticated = true
        // Without `channels_join` on the server a missing channel is not asked for.
        if (!canJoin) joinAsked = true
        deviceName = device?.name
        // Older servers may leave the flag out; then only the subscription can tell.
        radioConnected = device?.connected ?: true
        if (!radioConnected) {
            state = SessionState.NoRadio
            return Action.None
        }
        return startSubscribe()
    }

    @Synchronized
    fun onDevice(update: DeviceUpdate): Action {
        if (!authenticated) return Action.None
        sendsDeviceMessages = true
        update.device?.name?.let { deviceName = it }
        val connected = update.connected
        val wasConnected = radioConnected
        radioConnected = connected
        if (!connected) {
            // A subscription stays in place across the radio going away and coming back.
            state = SessionState.NoRadio
            return Action.None
        }
        if (busy) return Action.None
        if (subscribed) {
            state = SessionState.Connected(deviceName, unknownRegion)
            return Action.None
        }
        return when {
            update.hasChannel(channelName) -> startSubscribe()
            // The radio is back: the subscription says whether the channel is there.
            !wasConnected || state == SessionState.NoRadio -> startSubscribe()
            else -> Action.None
        }
    }

    @Synchronized
    fun onSubscribeAnswer(answer: ApiResult<String>): Action {
        busy = false
        if (answer.isOk) {
            subscribed = true
            state = SessionState.Connected(deviceName, unknownRegion)
            return Action.None
        }
        val code = answer.errorCode
        return when {
            code == ErrorCodes.NOT_CONNECTED -> {
                radioConnected = false
                state = SessionState.NoRadio
                Action.None
            }
            code != ErrorCodes.UNKNOWN_CHANNEL -> {
                state = SessionState.Refused(code)
                Action.None
            }
            !radioConnected -> {
                state = SessionState.NoRadio
                Action.None
            }
            clock() < deniedUntil -> {
                state = SessionState.ChannelDenied
                Action.None
            }
            joinAsked -> {
                if (state != SessionState.ChannelDenied && state !is SessionState.ChannelMissing) {
                    state = SessionState.ChannelMissing(null)
                }
                Action.None
            }
            else -> {
                joinAsked = true
                busy = true
                state = SessionState.WaitingForChannel
                Action.Join
            }
        }
    }

    @Synchronized
    fun onJoinAnswer(answer: ApiResult<*>): Action {
        busy = false
        if (answer.isOk) return startSubscribe()
        when (val code = answer.errorCode) {
            ErrorCodes.DENIED -> {
                deniedUntil = clock() + deniedPauseMs
                state = SessionState.ChannelDenied
            }
            ErrorCodes.NOT_CONNECTED -> {
                radioConnected = false
                state = SessionState.NoRadio
            }
            else -> state = SessionState.ChannelMissing(code)
        }
        return Action.None
    }

    /**
     * True when this connection is stuck without a subscription and the server does not send
     * `device` pushes that would end it: the session then refreshes `device.info` and subscribes.
     */
    @Synchronized
    fun retryDue(): Boolean = authenticated && !sendsDeviceMessages && !subscribed && !busy

    /** The fallback retry: [deviceInfo] is the `device.info` answer, if there was one. */
    @Synchronized
    fun onRetry(deviceInfo: ApiResult<DeviceUpdate>?): Action {
        if (!retryDue()) return Action.None
        deviceInfo?.valueOrNull?.device?.let { d ->
            d.name?.let { deviceName = it }
            d.connected?.let { radioConnected = it }
        }
        if (!radioConnected) {
            state = SessionState.NoRadio
            return Action.None
        }
        return startSubscribe()
    }

    /** Records a `channel.sendData` answer; true when the datagram was queued. */
    @Synchronized
    fun onSendAnswer(answer: ApiResult<Unit>, region: String?): Boolean {
        val code = answer.errorCode
        val refusedRegion = region != null && (code == ErrorCodes.UNKNOWN_REGION || code == ErrorCodes.BAD_REQUEST)
        val next = when {
            answer.isOk -> null
            refusedRegion -> region
            else -> unknownRegion
        }
        if (next != unknownRegion) {
            unknownRegion = next
            if (subscribed && radioConnected) state = SessionState.Connected(deviceName, unknownRegion)
        }
        return answer.isOk
    }

    private fun startSubscribe(): Action {
        busy = true
        return Action.Subscribe
    }

    companion object {
        /** After the user refused to add the channel, do not ask again for this long. */
        const val DENIED_PAUSE_MS = 10 * 60 * 1000L
    }
}
