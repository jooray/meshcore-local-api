package io.github.jooray.meshcore.localapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingTest {
    private val nonce = "AbCdEfGhIjKlMnOpQrStUv_-"

    private fun challenge(message: String?, n: String = nonce): JsonObject = Json.parseToJsonElement(
        """{"type":"pairing.challenge","protocol":1,"nonce":"$n"""" +
            (message?.let { ""","message":"$it"""" } ?: "") + "}"
    ).jsonObject

    @Test
    fun `the protocol prefix is signed exactly as sent`() {
        assertEquals("meshcore-local-api-pair-v1:$nonce", Pairing.messageToSign(challenge("meshcore-local-api-pair-v1:$nonce")))
    }

    @Test
    fun `anything else is refused`() {
        assertNull("old meshcore-open prefix", Pairing.messageToSign(challenge("meshcore-open-pair-v1:$nonce")))
        assertNull("foreign string", Pairing.messageToSign(challenge("please sign this transaction")))
        assertNull("other nonce", Pairing.messageToSign(challenge("meshcore-local-api-pair-v1:XXXXXXXXXXXXXXXXXXXX")))
        assertNull("suffix", Pairing.messageToSign(challenge("meshcore-local-api-pair-v1:$nonce:extra")))
        assertNull("no message", Pairing.messageToSign(challenge(null)))
        assertNull("short nonce", Pairing.messageToSign(challenge("meshcore-local-api-pair-v1:abc", n = "abc")))
        assertNull("bad nonce", Pairing.messageToSign(challenge("meshcore-local-api-pair-v1:a b", n = "a b")))
    }

    @Test
    fun `identity round trips through the store format and signs DER`() {
        val store = InMemoryKeyStore()
        val first = ClientIdentity.loadOrCreate(store)
        assertNotNull(store.load())
        val again = ClientIdentity.loadOrCreate(store)
        assertArrayEquals(first.publicKeyRaw, again.publicKeyRaw)
        assertEquals(64, first.publicKeyRaw.size)
        assertTrue(Regex("^[0-9A-F]{4}( [0-9A-F]{4}){3}$").matches(first.fingerprint))
        val sig = again.signBase64("meshcore-local-api-pair-v1:$nonce")
        assertTrue(FakeServer.verify(first.publicKeyRaw, "meshcore-local-api-pair-v1:$nonce", sig))
        // DER: a SEQUENCE.
        assertEquals(0x30, java.util.Base64.getDecoder().decode(sig)[0].toInt())
    }

    @Test
    fun `an unreadable stored identity is replaced`() {
        val store = InMemoryKeyStore("not json")
        val id = ClientIdentity.loadOrCreate(store)
        assertArrayEquals(id.publicKeyRaw, ClientIdentity.decode(store.load()!!)!!.publicKeyRaw)
    }
}
