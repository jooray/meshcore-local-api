package io.github.jooray.meshcore.localapi

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.TimeUnit

/** The session against [FakeServer]: subscribe, replay, device pushes, reconnect. */
class SessionTest {
    private val server = FakeServer()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val keys = InMemoryKeyStore()
    private val sessions = mutableListOf<MeshApiSession>()

    @After
    fun tearDown() {
        sessions.forEach { it.stop() }
        scope.cancel()
        server.close()
    }

    private fun session(
        cursor: CursorStore? = null,
        extra: Map<String, List<Int>> = emptyMap(),
        backoff: MeshApiSession.Backoff = MeshApiSession.Backoff(initialMs = 50, maxMs = 200, refusedMs = 300),
    ): MeshApiSession = MeshApiSession(
        MeshApiSession.Config(
            clientName = "Test app", clientVersion = "1.0", channel = "#test", dataTypes = listOf(0x0150),
            extraChannels = extra, url = server.url, backoff = backoff,
        ),
        keys, scope, cursor,
    ).also { sessions += it }

    /** Collects datagrams into a list from now on. */
    private suspend fun collect(s: MeshApiSession): MutableList<MeshEvent.ChannelData> {
        val list = Collections.synchronizedList(mutableListOf<MeshEvent.ChannelData>())
        // Undispatched: the collector is registered before this returns.
        scope.launch(start = CoroutineStart.UNDISPATCHED) { s.datagrams.collect { list += it } }
        return list
    }

    private suspend fun connected(s: MeshApiSession) = withTimeout(5_000) { s.state.first { it is SessionState.Connected } }

    private suspend fun eventually(what: String, check: () -> Boolean) {
        try {
            withTimeout(5_000) { while (!check()) delay(10) }
        } catch (e: Exception) {
            throw AssertionError("never: $what")
        }
    }

    @Test
    fun `connects, subscribes and delivers only its own datagrams`() = runBlocking<Unit> {
        val s = session()
        val got = collect(s)
        s.start()
        assertEquals(SessionState.Connected("Test node"), connected(s))
        val sub = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertEquals("#test", sub["channel"]!!.jsonPrimitive.content)
        assertEquals("[336]", sub["dataTypes"].toString())
        assertFalse("no cursor yet", sub.containsKey("since"))

        val conn = server.nextConnection()
        conn.event("s1", FakeServer.dataEvent(dataType = 0x0999))
        conn.event("s1", FakeServer.dataEvent(outgoing = true))
        conn.event("s1", FakeServer.dataEvent(channel = "Public"))
        conn.event("s1", FakeServer.dataEvent(payload = byteArrayOf(7)))
        eventually("one datagram") { got.size == 1 }
        delay(100)
        assertEquals(1, got.size)
        assertEquals(7, got[0].payload[0].toInt())
        assertTrue(keys.load() != null)
    }

    @Test
    fun `no radio at hello waits for a device push, then subscribes`() = runBlocking<Unit> {
        server.deviceConnected = false
        val s = session()
        s.start()
        withTimeout(5_000) { s.state.first { it == SessionState.NoRadio } }
        val conn = server.nextConnection()
        assertNull("no subscribe without a radio", server.requests.poll(200, TimeUnit.MILLISECONDS))
        server.deviceConnected = true
        conn.pushDevice(true)
        server.nextRequest("events.subscribe")
        connected(s)
        assertEquals(true, s.device.value!!.connected)
    }

    @Test
    fun `a failed subscription is retried on a device push with the radio`() = runBlocking<Unit> {
        server.channels.clear()
        server.joinError = "denied"
        val s = session()
        s.start()
        withTimeout(5_000) { s.state.first { it == SessionState.ChannelDenied } }
        // The user adds the channel on the server.
        server.channels.add("#test")
        server.nextConnection().pushDevice(true)
        connected(s)
    }

    @Test
    fun `a missing channel is joined, then subscribed`() = runBlocking<Unit> {
        server.channels.clear()
        val s = session()
        s.start()
        connected(s)
        server.nextRequest("channels.join")
        assertTrue("#test" in server.channels)
    }

    @Test
    fun `since replay is deduplicated across reconnects and restarts`() = runBlocking<Unit> {
        val a = FakeServer.dataEvent(payload = byteArrayOf(1), receivedAt = "2026-01-01T10:00:00.000Z")
        val b = FakeServer.dataEvent(payload = byteArrayOf(2), receivedAt = "2026-01-01T10:05:00.000Z")
        server.archive += listOf(a, b)
        val cursor = InMemoryCursorStore()

        // First run: no cursor, no replay. The live frame `a` moves the cursor.
        val s = session(cursor)
        val got = collect(s)
        s.start()
        connected(s)
        val conn = server.nextConnection()
        conn.event("s1", a)
        eventually("a") { got.size == 1 }
        assertTrue(cursor.load()!!.startsWith("2026-01-01T10:00:00.000Z "))

        // The server drops the link: the session reconnects with since = a, the server replays
        // a (inclusive) and b; only b is new.
        server.requests.clear()
        conn.close(1001, "server stopping")
        val sub = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertEquals("2026-01-01T10:00:00.000Z", sub["since"]!!.jsonPrimitive.content)
        eventually("b") { got.size == 2 }
        delay(200)
        assertEquals(listOf(1, 2), got.map { it.payload[0].toInt() })
        s.stop()
        server.connections.clear()
        server.requests.clear()

        // A new process with the stored cursor: b comes back (inclusive) and is dropped.
        val s2 = session(cursor)
        val got2 = collect(s2)
        s2.start()
        connected(s2)
        val sub2 = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertEquals("2026-01-01T10:05:00.000Z", sub2["since"]!!.jsonPrimitive.content)
        val c = FakeServer.dataEvent(payload = byteArrayOf(3), receivedAt = "2026-01-01T10:06:00.000Z")
        server.nextConnection().event("s9", c)
        eventually("c") { got2.size == 1 }
        delay(100)
        assertEquals(listOf(3), got2.map { it.payload[0].toInt() })
    }

    @Test
    fun `reconnects after the server goes away`() = runBlocking<Unit> {
        val s = session()
        s.start()
        connected(s)
        val conn = server.nextConnection()
        conn.close(1001, "server stopping")
        withTimeout(5_000) { s.state.first { it !is SessionState.Connected } }
        connected(s)
        assertTrue(server.connectionCount.get() >= 2)
    }

    @Test
    fun `a refused app waits the refused delay and says so`() = runBlocking<Unit> {
        server.refusePairing = true
        val s = session()
        s.start()
        withTimeout(5_000) { s.state.first { it == SessionState.NotApproved } }
        server.refusePairing = false
        connected(s)
    }

    @Test
    fun `zero-hop only with the capability`() = runBlocking<Unit> {
        val s = session()
        s.start()
        connected(s)
        assertEquals(ErrorCodes.UNSUPPORTED, s.sendData(byteArrayOf(1), route = Route.ZeroHop).errorCode)
        assertFalse(s.canSendPath)
        s.stop()

        server.capabilities = FakeServer.BASE + Capabilities.TX_PATH_DATA
        val s2 = session()
        s2.start()
        connected(s2)
        assertTrue(s2.canSendPath)
        server.requests.clear()
        assertTrue(s2.sendData(byteArrayOf(1), region = "xx-test", route = Route.ZeroHop).isOk)
        val p = server.nextRequest("channel.sendData")["params"] as JsonObject
        assertEquals("", p["path"]!!.jsonPrimitive.content)
        assertFalse(p.containsKey("region"))
    }

    @Test
    fun `a refused region shows until a send goes through`() = runBlocking<Unit> {
        val s = session()
        s.start()
        connected(s)
        server.handler = { _, method, _ ->
            if (method == "channel.sendData") FakeServer.error(kotlinx.serialization.json.JsonNull, "unknown_region") else null
        }
        assertEquals(ErrorCodes.UNKNOWN_REGION, s.sendData(byteArrayOf(1), region = "xx-test").errorCode)
        assertEquals(SessionState.Connected("Test node", "xx-test"), s.state.value)
        server.handler = null
        assertTrue(s.sendData(byteArrayOf(1)).isOk)
        assertEquals(SessionState.Connected("Test node"), s.state.value)
    }

    @Test
    fun `without replay the cursor is not sent`() = runBlocking<Unit> {
        server.capabilities = FakeServer.BASE - Capabilities.REPLAY
        val s = session(InMemoryCursorStore("2026-01-01T10:00:00.000Z"))
        s.start()
        connected(s)
        val sub = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertFalse(sub.containsKey("since"))
    }

    @Test
    fun `with replay the cursor is sent`() = runBlocking<Unit> {
        val s = session(InMemoryCursorStore("2026-01-01T10:00:00.000Z"))
        s.start()
        connected(s)
        val sub = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertEquals("2026-01-01T10:00:00.000Z", sub["since"]!!.jsonPrimitive.content)
    }

    @Test
    fun `without regions a send goes out without its region`() = runBlocking<Unit> {
        server.capabilities = FakeServer.BASE - Capabilities.REGIONS
        val s = session()
        s.start()
        connected(s)
        server.requests.clear()
        assertTrue(s.sendData(byteArrayOf(1), region = "xx-test").isOk)
        val p = server.nextRequest("channel.sendData")["params"] as JsonObject
        assertFalse(p.containsKey("region"))
        assertEquals(SessionState.Connected("Test node"), s.state.value)
    }

    @Test
    fun `without channels_join a missing channel is not asked for`() = runBlocking<Unit> {
        server.capabilities = FakeServer.BASE - Capabilities.CHANNELS_JOIN
        server.channels.clear()
        val s = session()
        s.start()
        withTimeout(5_000) { s.state.first { it == SessionState.ChannelMissing(null) } }
        delay(200)
        assertTrue(server.requests.none { it["method"]!!.jsonPrimitive.content == "channels.join" })
    }

    @Test
    fun `extra channels are subscribed after the main one`() = runBlocking<Unit> {
        server.channels.add("#extra")
        val s = session(extra = mapOf("#extra" to listOf(0x0222)))
        val got = collect(s)
        s.start()
        connected(s)
        server.nextRequest("events.subscribe")
        val extra = server.nextRequest("events.subscribe")["params"] as JsonObject
        assertEquals("#extra", extra["channel"]!!.jsonPrimitive.content)
        server.nextConnection().event("s2", FakeServer.dataEvent(channel = "#extra", dataType = 0x0222))
        eventually("extra datagram") { got.size == 1 }
        assertEquals("#extra", got[0].channel)
    }
}
