package io.github.jooray.meshcore.localapi

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.TimeUnit

/** The low-level client against [FakeServer]. */
class ClientTest {
    private val server = FakeServer()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val identity = ClientIdentity.generate()

    @After
    fun tearDown() {
        scope.cancel()
        server.close()
    }

    private fun client(timeouts: Timeouts = Timeouts()) =
        MeshCoreApiClient(identity, "Test app", "1.0", scope, server.url, timeouts = timeouts)

    @Test
    fun `handshake with the protocol prefix`() = runBlocking<Unit> {
        server.capabilities = listOf("tx_path_data", "rx_path", "future_thing")
        val c = client()
        val hello = withTimeout(5_000) { c.connect() }
        assertEquals(setOf("tx_path_data", "rx_path", "future_thing"), hello.capabilities)
        assertTrue(c.has(Capabilities.TX_PATH_DATA))
        assertEquals(163, c.limits!!.maxPayloadBytes)
        assertEquals("Test node", c.device.value!!.device!!.name)
        assertEquals(RadioParams(11, 250000, 5, 869525000L), hello.device!!.radio)
        assertTrue(c.state.value is ConnectionState.Ready)
        c.close()
    }

    @Test
    fun `the old meshcore-open prefix is refused`() = runBlocking<Unit> {
        server.challengeMessage = { "meshcore-open-pair-v1:$it" }
        val c = client()
        try {
            withTimeout(5_000) { c.connect() }
            fail("connected")
        } catch (e: MeshApiException.BadChallenge) {
            // expected
        }
        assertNull("no pair frame was sent", server.pairs.poll(300, TimeUnit.MILLISECONDS))
    }

    @Test
    fun `features without their capability are refused locally and nothing is sent`() = runBlocking<Unit> {
        server.capabilities = emptyList()
        val c = client()
        withTimeout(5_000) { c.connect() }
        server.requests.clear()
        fun check(cap: String, r: ApiResult<*>) {
            assertEquals(ErrorCodes.UNSUPPORTED, r.errorCode)
            assertEquals(cap, (r as ApiResult.Failed).error.missingCapability)
        }
        check("channels_join", c.joinChannel("#new"))
        check("regions", c.resolveRegion(0.0, 0.0))
        check("radio_stats", c.radioStats())
        check("contacts", c.contactsList())
        check("contacts", c.sendDirectText("ab", "hi"))
        check("advert_send", c.advertSend())
        check("regions", c.sendData("#test", 336, byteArrayOf(1), region = "xx-test"))
        check("tx_path_data", c.sendData("#test", 336, byteArrayOf(1), route = Route.ZeroHop))
        check("replay", c.subscribe(EventFilter.channelData("#test", listOf(336), since = "2026-01-01T10:00:00.000Z")))
        check("contacts", c.subscribe(EventFilter(events = listOf("advert"))))
        check("regions", c.sendText("#test", "hi", region = "xx-test"))
        assertEquals("unsupported", c.request("regions.list").errorCode)
        assertNull("nothing reached the server", server.requests.poll(200, TimeUnit.MILLISECONDS))
        // Core methods need no capability.
        assertTrue(c.sendData("#test", 336, byteArrayOf(1)).isOk)
        assertTrue(c.subscribe(EventFilter.channelData("#test", listOf(336))).isOk)
        assertTrue(c.deviceInfo().isOk)
        c.close()
    }

    @Test
    fun `a foreign challenge message is not signed`() = runBlocking<Unit> {
        server.challengeMessage = { "sign-anything:$it" }
        val c = client()
        try {
            withTimeout(5_000) { c.connect() }
            fail("connected")
        } catch (e: MeshApiException.BadChallenge) {
            // expected
        }
        assertNull("no pair frame was sent", server.pairs.poll(300, TimeUnit.MILLISECONDS))
        assertTrue(c.state.value is ConnectionState.Closed)
    }

    @Test
    fun `a challenge without message is not signed`() = runBlocking<Unit> {
        server.challengeMessage = { null }
        try {
            withTimeout(5_000) { client().connect() }
            fail("connected")
        } catch (e: MeshApiException.BadChallenge) {
            // expected
        }
        Unit
    }

    @Test
    fun `refused pairing is reported as refused`() = runBlocking<Unit> {
        server.refusePairing = true
        val c = client()
        try {
            withTimeout(5_000) { c.connect() }
            fail("connected")
        } catch (e: MeshApiException.Refused) {
            assertEquals(ErrorCodes.UNAUTHORIZED, e.error?.code)
        }
        assertTrue((c.state.value as ConnectionState.Closed).refused)
    }

    @Test
    fun `requests are matched by id and errors are typed`() = runBlocking<Unit> {
        val c = client()
        withTimeout(5_000) { c.connect() }
        val a = async { c.deviceInfo() }
        val b = async { c.request("no.such.method") }
        val info = a.await()
        assertEquals("Test node", info.valueOrNull!!.device!!.name)
        assertTrue(info.valueOrNull!!.hasChannel("#test"))
        assertEquals(ErrorCodes.UNKNOWN_METHOD, b.await().errorCode)
        assertEquals(ErrorCodes.UNKNOWN_CHANNEL, c.subscribe(EventFilter.channelData("#nope", listOf(1))).errorCode)
        assertEquals("s1", c.subscribe(EventFilter.channelData("#test", listOf(1))).valueOrNull)
        c.close()
    }

    @Test
    fun `a request without an answer times out, a closed socket answers disconnected`() = runBlocking<Unit> {
        server.handler = { _, _, _ -> null }
        val c = client(Timeouts(requestMs = 300))
        withTimeout(5_000) { c.connect() }
        assertEquals(ApiResponse.Timeout, c.request("device.info"))
        val pending = async(Dispatchers.IO) { c.request("device.info", timeoutMs = 5_000) }
        server.nextRequest("device.info")
        server.nextRequest("device.info")
        c.close()
        assertEquals(ApiResponse.NotConnected, withTimeout(5_000) { pending.await() })
        assertEquals(ApiResponse.NotConnected, c.request("device.info"))
    }

    @Test
    fun `channels join gets the long timeout`() {
        val t = Timeouts()
        assertEquals(150_000L, t.forMethod("channels.join"))
        assertEquals(15_000L, t.forMethod("channel.sendData"))
    }

    @Test
    fun `device pushes update the state flow`() = runBlocking<Unit> {
        val c = client()
        withTimeout(5_000) { c.connect() }
        val conn = server.nextConnection()
        conn.pushDevice(false)
        val off = withTimeout(5_000) { c.device.first { it?.channels != null } }
        assertFalse(off!!.connected)
        conn.pushDevice(true)
        val on = withTimeout(5_000) { c.device.first { it?.connected == true && it.channels != null } }
        assertTrue(on!!.hasChannel("#test"))
        c.close()
    }

    @Test
    fun `events are parsed in order and unknown types skipped`() = runBlocking<Unit> {
        val c = client()
        withTimeout(5_000) { c.connect() }
        val conn = server.nextConnection()
        // Undispatched: the collector is registered before the events are sent.
        val got = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { withTimeout(5_000) { c.events.first() } }
        conn.event("s1", buildJsonObject { put("type", "send.result"); put("sendId", "x") })
        conn.event("s1", FakeServer.dataEvent(payload = byteArrayOf(9, 8)))
        val e = got.await()
        assertEquals("s1", e.subscriptionId)
        assertArrayEquals(byteArrayOf(9, 8), (e.event as MeshEvent.ChannelData).payload)
        c.close()
    }

    @Test
    fun `path is sent only with tx_path_data`() = runBlocking<Unit> {
        val c = client()
        withTimeout(5_000) { c.connect() }
        val refused = c.sendData("#test", 336, byteArrayOf(1), route = Route.ZeroHop)
        assertEquals(ErrorCodes.UNSUPPORTED, refused.errorCode)
        assertEquals(Capabilities.TX_PATH_DATA, (refused as ApiResult.Failed).error.missingCapability)
        assertTrue(c.sendData("#test", 336, byteArrayOf(1), region = "xx-test").isOk)
        val flood = server.nextRequest("channel.sendData")["params"] as kotlinx.serialization.json.JsonObject
        assertFalse(flood.containsKey("path"))
        assertEquals("xx-test", flood["region"]!!.jsonPrimitive.content)
        assertNull("nothing else was sent", server.requests.poll(200, TimeUnit.MILLISECONDS))
        c.close()

        server.capabilities = FakeServer.BASE + "tx_path_data"
        val c2 = client()
        withTimeout(5_000) { c2.connect() }
        assertTrue(c2.sendData("#test", 336, byteArrayOf(1), region = "xx-test", route = Route.ZeroHop).isOk)
        val zero = server.nextRequest("channel.sendData")["params"] as kotlinx.serialization.json.JsonObject
        assertEquals("", zero["path"]!!.jsonPrimitive.content)
        assertEquals("1", zero["pathHashSize"]!!.jsonPrimitive.content)
        assertFalse(zero.containsKey("region"))
        assertEquals(ErrorCodes.BAD_REQUEST, c2.sendData("#test", 336, byteArrayOf(1), route = Route.Direct(ByteArray(3), 2)).errorCode)
        c2.close()
    }

    @Test
    fun `a client is single use`() = runBlocking<Unit> {
        val c = client()
        withTimeout(5_000) { c.connect() }
        try {
            c.connect()
            fail("second connect")
        } catch (e: IllegalStateException) {
            // expected
        }
        c.close()
    }
}
