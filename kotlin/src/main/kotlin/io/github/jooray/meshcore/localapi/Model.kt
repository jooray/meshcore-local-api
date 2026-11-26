package io.github.jooray.meshcore.localapi

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import java.time.Instant
import java.util.Base64

/**
 * Optional server features named in `hello.capabilities` (SPEC.md section 13). The client never
 * uses a feature whose name is absent.
 */
object Capabilities {
    /** `contacts.list`, `direct.sendText`, events `direct.text` and `advert`, filter `pubkeys`. */
    const val CONTACTS = "contacts"
    /** `advert.send`. */
    const val ADVERT_SEND = "advert_send"
    /** `regions.list`, `regions.resolve`, `region` on sends. */
    const val REGIONS = "regions"
    /** `channels.join`. */
    const val CHANNELS_JOIN = "channels_join"
    /** The channel data archive and `since` in `events.subscribe`. */
    const val REPLAY = "replay"
    const val REPLAY_TEXT = "replay_text"
    /** `radio.stats`. */
    const val RADIO_STATS = "radio_stats"
    /** `channel.sendData` takes `path` / `pathHashSize` (zero-hop and direct sends). */
    const val TX_PATH_DATA = "tx_path_data"
    const val TX_PATH_TEXT = "tx_path_text"
    /** Received events carry `path` / `pathHashSize` / `routeType`. */
    const val RX_PATH = "rx_path"
    /** Received events carry `snrDb`, `rssiDbm`, `hops`, `routeType`. */
    const val RX_META = "rx_meta"
    /** Received events carry `transportCode` and, when the server matched one name, `scope` (section 8.14). */
    const val RX_SCOPE = "rx_scope"
    /** Received events the radio held in its offline queue carry `queued: true` (section 8.15). */
    const val RX_QUEUED = "rx_queued"
    /** `channel.sendData` takes `"priority": "now"` and its result carries `sentAt`. */
    const val TX_NOW = "tx_now"
    /** `radio.reboot`: reboot the radio by command (section 8.17). */
    const val RADIO_REBOOT = "radio_reboot"
    const val RAW_RX = "raw_rx"
    const val RAW_TX = "raw_tx"
    const val TX_RESULT = "tx_result"
    /** `radio.stats` reports airtime and the LoRa preset. */
    const val AIRTIME = "airtime"
    const val DUTY_CAP = "duty_cap"
    const val NOISE_FLOOR = "noise_floor"
}

/** Error codes the server sends, plus [TIMEOUT] and [DISCONNECTED] that this client makes up. */
object ErrorCodes {
    const val UNAUTHORIZED = "unauthorized"
    const val PAIRING_PENDING = "pairing_pending"
    const val RATE_LIMITED = "rate_limited"
    const val TOO_MANY_CLIENTS = "too_many_clients"
    const val BAD_REQUEST = "bad_request"
    const val UNKNOWN_METHOD = "unknown_method"
    const val NOT_CONNECTED = "not_connected"
    const val UNSUPPORTED_FIRMWARE = "unsupported_firmware"
    const val UNSUPPORTED = "unsupported"
    const val INVALID_PARAMS = "invalid_params"
    const val DENIED = "denied"
    const val NO_FREE_SLOT = "no_free_slot"
    const val CHANNEL_CONFLICT = "channel_conflict"
    const val UNKNOWN_CHANNEL = "unknown_channel"
    const val AMBIGUOUS_CHANNEL = "ambiguous_channel"
    const val UNKNOWN_CONTACT = "unknown_contact"
    const val UNKNOWN_REGION = "unknown_region"
    const val COORDINATE_RANGE = "coordinate_range"
    const val PAYLOAD_TOO_LARGE = "payload_too_large"
    const val INVALID_DATA_TYPE = "invalid_data_type"
    const val RADIO_ERROR = "radio_error"
    const val INTERNAL = "internal"

    /** Client side: no answer within the request's timeout. */
    const val TIMEOUT = "timeout"
    /** Client side: no open connection, or it closed before the answer. */
    const val DISCONNECTED = "disconnected"
}

/** A typed answer: the value, or why there is none (a server code or [ErrorCodes.TIMEOUT] / [ErrorCodes.DISCONNECTED]). */
sealed interface ApiResult<out T> {
    data class Ok<T>(val value: T) : ApiResult<T>
    data class Failed(val error: ApiError) : ApiResult<Nothing>

    val isOk: Boolean get() = this is Ok
    val valueOrNull: T? get() = (this as? Ok)?.value
    val errorCode: String? get() = (this as? Failed)?.error?.code
}

internal fun <T> ApiResponse.toResult(map: (JsonObject) -> T?): ApiResult<T> = when (this) {
    is ApiResponse.Ok -> map(result)?.let { ApiResult.Ok(it) }
        ?: ApiResult.Failed(ApiError(ErrorCodes.INTERNAL, "malformed result"))
    is ApiResponse.Error -> ApiResult.Failed(error)
    ApiResponse.Timeout -> ApiResult.Failed(ApiError(ErrorCodes.TIMEOUT))
    ApiResponse.NotConnected -> ApiResult.Failed(ApiError(ErrorCodes.DISCONNECTED))
}

/** One entry of `contacts.list`. */
data class Contact(val pubkey: String, val name: String?, val type: Int?, val lastSeen: String?)

/** `channels.join` result. */
data class JoinResult(val index: Int?, val name: String, val created: Boolean)

/** Close codes the server uses. */
object CloseCodes {
    const val NORMAL = 1000
    const val GOING_AWAY = 1001
    const val UNSUPPORTED_DATA = 1003
    const val TOO_BIG = 1009
    const val HANDSHAKE = 4001
    /** Key, signature or pairing rejected, or the app was revoked. */
    const val REFUSED = 4003
    /** Slow consumer or too many clients. */
    const val BUSY = 4013
}

/**
 * An error. [missingCapability] is set when this client refused the request itself because the
 * server does not list that capability ([code] is then [ErrorCodes.UNSUPPORTED]); nothing was sent.
 */
data class ApiError(val code: String, val message: String? = null, val missingCapability: String? = null) {
    companion object {
        fun missingCapability(name: String) =
            ApiError(ErrorCodes.UNSUPPORTED, "server lacks capability $name", missingCapability = name)
    }
}

/** The answer to one request. */
sealed interface ApiResponse {
    data class Ok(val result: JsonObject) : ApiResponse
    data class Error(val error: ApiError) : ApiResponse
    /** No answer within the request's timeout. */
    data object Timeout : ApiResponse
    /** The socket was not open, or closed before the answer came. */
    data object NotConnected : ApiResponse

    val isOk: Boolean get() = this is Ok
    /** The server's error code, null for success, timeout or no connection. */
    val errorCode: String? get() = (this as? Error)?.error?.code
    val resultOrNull: JsonObject? get() = (this as? Ok)?.result

    companion object {
        /** A response frame (`{"id":…,"ok":…}`) as a typed answer. */
        fun parse(message: JsonObject): ApiResponse {
            if ((message["ok"] as? JsonPrimitive)?.booleanOrNull == true) {
                return Ok(message["result"] as? JsonObject ?: JsonObject(emptyMap()))
            }
            val error = message["error"] as? JsonObject
            return Error(
                ApiError(
                    code = error?.string("code") ?: ErrorCodes.INTERNAL,
                    message = error?.string("message"),
                )
            )
        }
    }
}

/** LoRa modulation as `device.radio` or `radio.stats.preset` report it. */
data class RadioParams(
    val sf: Int,
    val bwHz: Int,
    /** Coding rate as the denominator, 5..8 (4/5..4/8). */
    val cr: Int,
    val freqHz: Long? = null,
    val txPowerDbm: Int? = null,
) {
    companion object {
        /** Null when a field is missing or out of range. A coding rate of 1..4 means 4/5..4/8. */
        fun parse(obj: JsonObject?): RadioParams? {
            obj ?: return null
            val sf = obj.int("sf") ?: return null
            val bw = obj.double("bwHz")?.toInt() ?: return null
            val crRaw = obj.int("cr") ?: return null
            val cr = if (crRaw in 1..4) crRaw + 4 else crRaw
            if (sf !in 5..12 || bw <= 0 || cr !in 5..8) return null
            return RadioParams(sf, bw, cr, obj.long("freqHz"), obj.int("txPowerDbm"))
        }
    }
}

/** `hello.device`, the `device` push, or the `device.info` result. */
data class DeviceInfo(
    /** Control characters removed, at most 64 characters; null when empty. */
    val name: String?,
    val pubkey: String?,
    val firmwareVerCode: Int?,
    /** Null when the server leaves the flag out (older servers). */
    val connected: Boolean?,
    val radio: RadioParams?,
    val batteryMv: Int?,
) {
    companion object {
        fun parse(obj: JsonObject?): DeviceInfo? {
            obj ?: return null
            return DeviceInfo(
                name = obj.string("name")?.filter { it.code >= 0x20 }?.take(64)?.ifEmpty { null },
                pubkey = obj.string("pubkey"),
                firmwareVerCode = obj.int("firmwareVerCode"),
                connected = (obj["connected"] as? JsonPrimitive)?.booleanOrNull,
                radio = RadioParams.parse(obj["radio"] as? JsonObject),
                batteryMv = obj.int("batteryMv"),
            )
        }
    }
}

data class ChannelInfo(val index: Int?, val name: String, val isPublic: Boolean?, val storageId: String?) {
    companion object {
        fun parseList(element: JsonElement?): List<ChannelInfo>? = (element as? JsonArray)?.mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val name = o.string("name") ?: return@mapNotNull null
            ChannelInfo(o.int("index"), name, (o["isPublic"] as? JsonPrimitive)?.booleanOrNull, o.string("storageId"))
        }
    }
}

/** What the server says about its radio: from `hello` ([channels] null) or a `device` push. */
data class DeviceUpdate(val device: DeviceInfo?, val channels: List<ChannelInfo>?) {
    /** The radio can be used. A missing flag counts as connected (older servers). */
    val connected: Boolean get() = device?.connected ?: true

    fun hasChannel(name: String): Boolean = channels?.any { it.name == name } == true

    companion object {
        fun parse(message: JsonObject): DeviceUpdate =
            DeviceUpdate(DeviceInfo.parse(message["device"] as? JsonObject), ChannelInfo.parseList(message["channels"]))
    }
}

/** `hello.limits`; every field null when the server does not report it. */
data class Limits(
    val maxPayloadBytes: Int? = null,
    val maxMessageBytes: Int? = null,
    val maxQueuedBytes: Int? = null,
    val sendsPerMinute: Int? = null,
    val minSendGapMs: Int? = null,
    val maxSubscriptions: Int? = null,
    val maxFilterEntries: Int? = null,
) {
    companion object {
        fun parse(obj: JsonObject?): Limits = if (obj == null) Limits() else Limits(
            obj.int("maxPayloadBytes"), obj.int("maxMessageBytes"), obj.int("maxQueuedBytes"),
            obj.int("sendsPerMinute"), obj.int("minSendGapMs"), obj.int("maxSubscriptions"),
            obj.int("maxFilterEntries"),
        )
    }
}

/** The server's `hello`, sent once pairing is done. */
data class Hello(
    val protocol: Int?,
    val clientFingerprint: String?,
    val device: DeviceInfo?,
    val eventTypes: List<String>,
    val limits: Limits,
    /** Top-level `hello.capabilities` only; empty when missing or malformed. */
    val capabilities: Set<String>,
    val raw: JsonObject,
) {
    companion object {
        fun parse(message: JsonObject): Hello = Hello(
            protocol = message.int("protocol"),
            clientFingerprint = (message["client"] as? JsonObject)?.string("fingerprint"),
            device = DeviceInfo.parse(message["device"] as? JsonObject),
            eventTypes = message.strings("eventTypes"),
            limits = Limits.parse(message["limits"] as? JsonObject),
            capabilities = message.strings("capabilities").toSet(),
            raw = message,
        )
    }
}

/** One event from the server. Unknown event types are not represented: [parse] returns null. */
sealed interface MeshEvent {
    /** ISO-8601 receive time on the server: the `since` replay cursor. */
    val receivedAt: String?
    val receivedAtMs: Long? get() = receivedAt?.let { parseInstantMs(it) }

    class ChannelData(
        val channel: String,
        val channelIndex: Int?,
        val dataType: Int,
        val payload: ByteArray,
        val snrDb: Double?,
        /** Flood hop count (0: heard from the sender's radio); null for a direct path or own sends. */
        val hops: Int?,
        override val receivedAt: String?,
        val outgoing: Boolean,
        /** `rx_path`: the path as it arrived, first hop first; empty for zero hops. */
        val path: ByteArray? = null,
        val pathHashSize: Int? = null,
        val routeType: String? = null,
        /** `rx_meta`. */
        val rssiDbm: Double? = null,
        /** `rx_scope`: the packet's first transport code (`code[0]`, 0..65535); null for a packet without one. */
        val transportCode: Int? = null,
        /** `rx_scope`: the flood-scope name (no leading `#`) the server matched to [transportCode], when exactly one did. */
        val scope: String? = null,
        /** `rx_queued`: the radio held this frame in its offline queue; its `receivedAt` is not the time on air. */
        val queued: Boolean = false,
    ) : MeshEvent {
        override fun equals(other: Any?): Boolean = other is ChannelData &&
            channel == other.channel && channelIndex == other.channelIndex && dataType == other.dataType &&
            payload.contentEquals(other.payload) && snrDb == other.snrDb && hops == other.hops &&
            receivedAt == other.receivedAt && outgoing == other.outgoing &&
            sameBytes(path, other.path) &&
            pathHashSize == other.pathHashSize && routeType == other.routeType && rssiDbm == other.rssiDbm &&
            transportCode == other.transportCode && scope == other.scope && queued == other.queued

        override fun hashCode(): Int =
            ((channel.hashCode() * 31 + dataType) * 31 + payload.contentHashCode()) * 31 + (receivedAt?.hashCode() ?: 0)

        override fun toString(): String =
            "ChannelData(channel=$channel, dataType=$dataType, ${payload.size} bytes, hops=$hops, receivedAt=$receivedAt)"
    }

    data class ChannelText(
        val channel: String,
        val channelIndex: Int?,
        val senderName: String?,
        val senderKeyHex: String?,
        val text: String,
        val sentAt: String?,
        val messageId: String?,
        override val receivedAt: String?,
        val outgoing: Boolean,
    ) : MeshEvent

    data class DirectText(
        val pubkey: String,
        val name: String?,
        val text: String,
        val sentAt: String?,
        val messageId: String?,
        override val receivedAt: String?,
        val outgoing: Boolean,
    ) : MeshEvent

    data class Advert(
        val pubkey: String,
        val name: String?,
        val nodeType: Int?,
        val lastSeen: String?,
        override val receivedAt: String?,
    ) : MeshEvent

    companion object {
        /** The `event` object of an `{"type":"event"}` frame; null for unknown types or bad fields. */
        fun parse(event: JsonObject): MeshEvent? = when (event.string("type")) {
            "channel.data" -> parseChannelData(event)
            "channel.text" -> {
                val channel = event.string("channel")
                val text = event.string("text")
                if (channel == null || text == null) null else ChannelText(
                    channel, event.int("channelIndex"), event.string("senderName"), event.string("senderKeyHex"),
                    text, event.anyString("sentAt"), event.anyString("messageId"), event.string("receivedAt"),
                    event.bool("outgoing") == true,
                )
            }
            "direct.text" -> {
                val pubkey = event.string("pubkey")
                val text = event.string("text")
                if (pubkey == null || text == null) null else DirectText(
                    pubkey, event.string("name"), text, event.anyString("sentAt"), event.anyString("messageId"),
                    event.string("receivedAt"), event.bool("outgoing") == true,
                )
            }
            "advert" -> event.string("pubkey")?.let {
                Advert(it, event.string("name"), event.int("nodeType"), event.anyString("lastSeen"), event.string("receivedAt"))
            }
            else -> null
        }

        private fun parseChannelData(event: JsonObject): ChannelData? {
            val channel = event.string("channel") ?: return null
            val dataType = event.int("dataType") ?: return null
            val payload = event.string("payload")?.let {
                try {
                    Base64.getDecoder().decode(it)
                } catch (e: IllegalArgumentException) {
                    null
                }
            } ?: return null
            val hashSize = event.int("pathHashSize")?.takeIf { it in 1..3 }
            val path = hexBytes(event.string("path"))?.takeIf { hashSize == null || it.size % hashSize == 0 }
            return ChannelData(
                channel = channel,
                channelIndex = event.int("channelIndex"),
                dataType = dataType,
                payload = payload,
                snrDb = event.double("snrDb"),
                hops = event.int("hops"),
                receivedAt = event.string("receivedAt"),
                outgoing = event.bool("outgoing") == true,
                path = path,
                pathHashSize = hashSize,
                routeType = event.string("routeType"),
                rssiDbm = event.double("rssiDbm"),
                transportCode = event.int("transportCode")?.takeIf { it in 0..0xFFFF },
                scope = event.string("scope")?.takeIf { it.isNotEmpty() },
                queued = event.bool("queued") == true,
            )
        }
    }
}

/** An event with the subscription that delivered it. */
data class ApiEvent(val subscriptionId: String?, val event: MeshEvent)

/** `events.subscribe` params. Filters are conjunctive on the server. */
data class EventFilter(
    /** Event types; null for all. */
    val events: List<String>? = null,
    val channel: String? = null,
    val dataTypes: List<Int>? = null,
    val pubkeys: List<String>? = null,
    /** Replay archived frames received at or after this ISO-8601 time (inclusive). */
    val since: String? = null,
) {
    fun toParams(): JsonObject = buildJsonObject {
        events?.let { list -> put("events", buildJsonArray { list.forEach { add(JsonPrimitive(it)) } }) }
        channel?.let { put("channel", it) }
        dataTypes?.let { list -> put("dataTypes", buildJsonArray { list.forEach { add(JsonPrimitive(it)) } }) }
        pubkeys?.let { list -> put("pubkeys", buildJsonArray { list.forEach { add(JsonPrimitive(it)) } }) }
        since?.let { put("since", it) }
    }

    companion object {
        /** Channel data of [dataTypes] on [channel]. */
        fun channelData(channel: String, dataTypes: List<Int>, since: String? = null) =
            EventFilter(events = listOf("channel.data"), channel = channel, dataTypes = dataTypes, since = since)
    }
}

/** How `channel.sendData` leaves the radio. Anything but [Flood] needs [Capabilities.TX_PATH_DATA]. */
sealed interface Route {
    /** No `path`: the radio floods (scoped by `region`, if given). */
    data object Flood : Route

    /** `"path": ""`: only radios in range of ours hear it, no repeater forwards it. */
    data object ZeroHop : Route

    /** Along [path]: repeater hashes in sending order, [hashSize] (1..3) bytes each. */
    class Direct(val path: ByteArray, val hashSize: Int = 1) : Route {
        val hops: Int get() = if (hashSize > 0) path.size / hashSize else 0

        /** At most 64 bytes and 63 hops, a whole number of hashes, hash size 1..3. */
        val valid: Boolean
            get() = hashSize in 1..3 && path.isNotEmpty() && path.size <= 64 && path.size % hashSize == 0 && hops <= 63

        override fun equals(other: Any?) = other is Direct && hashSize == other.hashSize && path.contentEquals(other.path)
        override fun hashCode() = path.contentHashCode() * 31 + hashSize
        override fun toString() = "Direct(${path.toHex()}/$hashSize)"
    }
}

internal fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

/** A string or a number as text (ids and times that some servers send as numbers). */
internal fun JsonObject.anyString(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.contentOrNull

internal fun JsonObject.int(key: String): Int? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.intOrNull
internal fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
internal fun JsonObject.double(key: String): Double? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull
internal fun JsonObject.bool(key: String): Boolean? = (this[key] as? JsonPrimitive)?.booleanOrNull

internal fun JsonObject.strings(key: String): List<String> =
    (this[key] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: emptyList()

private fun sameBytes(a: ByteArray?, b: ByteArray?): Boolean =
    if (a == null || b == null) a == null && b == null else a.contentEquals(b)

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

internal fun hexBytes(s: String?): ByteArray? {
    if (s == null || s.length % 2 != 0 || s.any { it !in "0123456789abcdefABCDEF" }) return null
    return ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

internal fun parseInstantMs(s: String): Long? = try {
    Instant.parse(s).toEpochMilli()
} catch (e: Exception) {
    null
}
