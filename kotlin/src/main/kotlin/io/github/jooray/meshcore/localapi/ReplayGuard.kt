package io.github.jooray.meshcore.localapi

import java.security.MessageDigest

/** Where a [MeshApiSession] keeps its replay cursor between runs. The string is opaque. */
interface CursorStore {
    fun load(): String?
    fun save(cursor: String)
}

class InMemoryCursorStore(private var value: String? = null) : CursorStore {
    @Synchronized override fun load(): String? = value
    @Synchronized override fun save(cursor: String) { value = cursor }
}

/**
 * The `since` cursor and the duplicate filter for channel data.
 *
 * The server's `since` is inclusive, so the frame at the cursor comes back on every subscribe.
 * The cursor is the newest `receivedAt` seen plus short hashes of the frames received at exactly
 * that instant, stored as `<receivedAt> <hash>,<hash>`; a bare `<receivedAt>` (what the apps
 * stored before) is read too and then drops nothing at that instant but by recent memory.
 * Within one process the last [memory] frames are remembered as well, which covers reconnects
 * and several subscriptions replaying the same frame.
 */
internal class ReplayGuard(private val store: CursorStore?, private val memory: Int = 1024) {
    private var cursorAt: String? = null
    private var cursorMs: Long? = null
    private val cursorKeys = LinkedHashSet<String>()
    private val recent = object : LinkedHashMap<String, Unit>(64, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Unit>?) = size > memory
    }

    init {
        store?.load()?.trim()?.takeIf { it.isNotEmpty() }?.let { stored ->
            val parts = stored.split(' ', limit = 2)
            cursorAt = parts[0]
            cursorMs = parseInstantMs(parts[0])
            parts.getOrNull(1)?.split(',')?.filter { it.isNotBlank() }?.let { cursorKeys.addAll(it) }
        }
    }

    /** The `since` for the next subscriptions: the newest `receivedAt` seen. */
    @Synchronized
    fun since(): String? = cursorAt

    /** False when [frame] was delivered already. True records it as seen. */
    @Synchronized
    fun accept(frame: MeshEvent.ChannelData): Boolean {
        val at = frame.receivedAt ?: return true
        val key = contentKey(frame)
        if (recent.containsKey("$at $key")) return false
        if (at == cursorAt && key in cursorKeys) return false
        recent["$at $key"] = Unit
        return true
    }

    /** Moves the cursor forward to [frame] (never back) and stores it. */
    @Synchronized
    fun advance(frame: MeshEvent.ChannelData) {
        val at = frame.receivedAt ?: return
        val ms = parseInstantMs(at) ?: return
        val key = contentKey(frame)
        val current = cursorMs
        when {
            current == null || ms > current -> {
                cursorAt = at
                cursorMs = ms
                cursorKeys.clear()
                cursorKeys.add(key)
            }
            ms == current -> {
                if (!cursorKeys.add(key)) return
                while (cursorKeys.size > MAX_KEYS) cursorKeys.remove(cursorKeys.first())
            }
            else -> return
        }
        store?.save("$cursorAt ${cursorKeys.joinToString(",")}")
    }

    companion object {
        private const val MAX_KEYS = 16

        /** 8 bytes of SHA-256 over channel, data type and payload, hex. */
        fun contentKey(frame: MeshEvent.ChannelData): String {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(frame.channel.toByteArray(Charsets.UTF_8))
            md.update(0.toByte())
            md.update(frame.dataType.toString().toByteArray(Charsets.UTF_8))
            md.update(0.toByte())
            md.update(frame.payload)
            return md.digest().copyOf(8).toHex()
        }
    }
}
