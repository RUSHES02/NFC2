package com.example.nfc2

import android.app.PendingIntent
import android.content.ContentValues.TAG
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.os.Bundle
import android.os.Parcelable
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException
import java.nio.charset.Charset

class MainActivity : AppCompatActivity() {
    // Initialize attributes
    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private val key = byteArrayOf(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ) // Replace with your desired key

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize NfcAdapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        // If no NfcAdapter, display that the device has no NFC
        if (nfcAdapter == null) {
            Toast.makeText(
                this, "NO NFC Capabilities",
                Toast.LENGTH_SHORT
            ).show()
            finish()
        }
        // Create a PendingIntent object so the Android system can
        // populate it with the details of the tag when it is scanned.
        pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, this.javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )

        val button = findViewById<Button>(R.id.nextButton)
        button.setOnClickListener{
            recreate()
        }
    }

    override fun onResume() {
        super.onResume()
        assert(nfcAdapter != null)
        nfcAdapter!!.enableForegroundDispatch(this, pendingIntent, null, null)
    }

    override fun onPause() {
        super.onPause()
        // On pause, stop listening
        if (nfcAdapter != null) {
            nfcAdapter!!.disableForegroundDispatch(this)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        resolveIntent(intent)
    }

    private fun resolveIntent(intent: Intent) {
        val action = intent.action
        if (NfcAdapter.ACTION_TAG_DISCOVERED == action ||
            NfcAdapter.ACTION_TECH_DISCOVERED == action ||
            NfcAdapter.ACTION_NDEF_DISCOVERED == action
        ) {
            val tag = (intent.getParcelableExtra<Parcelable>(NfcAdapter.EXTRA_TAG) as Tag?)!!
//            readSector1Data(tag)
            readBlockData(tag)
            val payload = detectTagData(tag).toByteArray()
        }
    }

    // For detection
    private fun detectTagData(tag: Tag?): String {
        val sb = StringBuilder()
        val id = tag!!.id
        sb.append("ID (hex): ").append(toHex(id)).append('\n')
        sb.append("ID (reversed hex): ").append(toReversedHex(id)).append('\n')
        sb.append("ID (dec): ").append(toDec(id)).append('\n')
        sb.append("ID (reversed dec): ").append(toReversedDec(id)).append('\n')
        val prefix = "android.nfc.tech."
        sb.append("Technologies: ")
        for (tech in tag.techList) {
            sb.append(tech.substring(prefix.length))
            sb.append(", ")
        }
        sb.delete(sb.length - 2, sb.length)
        for (tech in tag.techList) {
            if (tech == MifareClassic::class.java.name) {
                sb.append('\n')
                var type = "Unknown"
                try {
                    val mifareTag = MifareClassic.get(tag)
                    when (mifareTag.type) {
                        MifareClassic.TYPE_CLASSIC -> type = "Classic"
                        MifareClassic.TYPE_PLUS -> type = "Plus"
                        MifareClassic.TYPE_PRO -> type = "Pro"
                    }
                    sb.append("Mifare Classic type: ")
                    sb.append(type)
                    sb.append('\n')
                    sb.append("Mifare size: ")
                    sb.append(mifareTag.size.toString() + " bytes")
                    sb.append('\n')
                    sb.append("Mifare sectors: ")
                    sb.append(mifareTag.sectorCount)
                    sb.append('\n')
                    sb.append("Mifare blocks: ")
                    sb.append(mifareTag.blockCount)
                    sb.append('\n')
                } catch (e: Exception) {
                    sb.append("Mifare classic error: " + e.message)
                }
            }
            if (tech == MifareUltralight::class.java.name) {
                sb.append('\n')
                val mifareUlTag = MifareUltralight.get(tag)
                var type = "Unknown"
                when (mifareUlTag.type) {
                    MifareUltralight.TYPE_ULTRALIGHT -> type = "Ultralight"
                    MifareUltralight.TYPE_ULTRALIGHT_C -> type = "Ultralight C"
                }
                sb.append("Mifare Ultralight type: ")
                sb.append(type)
            }
        }
//        Log.v(TAG, sb.toString())
        return sb.toString()
    }

    private fun readSector1Data(tag: Tag) {
        val mifareClassic = MifareClassic.get(tag)
        try {
            mifareClassic.connect()
            val sector = 1 // Read data from sector 1
            val keyList = getDefaultKeys()

            for (key in keyList) {
                if (mifareClassic.authenticateSectorWithKeyA(sector, key)) {
                    // Authentication successful, read the sector data here
                    val blockCount = mifareClassic.getBlockCountInSector(sector)
                    for (block in 0 until blockCount) {
                        val blockIndex = mifareClassic.sectorToBlock(sector) + block
                        val data = mifareClassic.readBlock(blockIndex)
                        val dataString = String(data, Charset.forName("US-ASCII"))
                        Log.d(TAG, "Block $blockIndex data: $dataString")
                    }
                    break
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error reading Mifare Classic tag data", e)
        } finally {
            try {
                mifareClassic.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing MifareClassic", e)
            }
        }
    }


    private fun readBlockData(tag: Tag) {
        val mifareClassic = MifareClassic.get(tag)
        try {
            mifareClassic.connect()
            val sector = 1 // Read data from sector 1
            val block = 0// Read data from block 4
            val keyList = getDefaultKeys()

            for (key in keyList) {
                if (mifareClassic.authenticateSectorWithKeyA(sector, key)) {
                    // Authentication successful, read the block data here
                    val blockIndex = mifareClassic.sectorToBlock(sector) + block
                    val data = mifareClassic.readBlock(blockIndex)
                    val dataString = String(data, Charset.forName("US-ASCII"))
                    val textView = findViewById<TextView>(R.id.rollNumberTextView)
                    textView.text = dataString.subSequence(0,8)
                    Log.d(TAG, "Block $blockIndex data: $dataString")
                    break
                }
            }
        } catch (e: IOException) {
            Log.e(TAG, "Error reading Mifare Classic tag data", e)
        } finally {
            try {
                mifareClassic.close()
            } catch (e: IOException) {
                Log.e(TAG, "Error closing MifareClassic", e)
            }
        }
    }

    private fun toHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (i in bytes.indices.reversed()) {
            val b = bytes[i].toInt() and 0xff
            if (b < 0x10) sb.append('0')
            sb.append(Integer.toHexString(b))
            if (i > 0) {
                sb.append(" ")
            }
        }
        return sb.toString()
    }

    private fun toReversedHex(bytes: ByteArray): String {
        val sb = StringBuilder()
        for (i in bytes.indices) {
            if (i > 0) {
                sb.append(" ")
            }
            val b = bytes[i].toInt() and 0xff
            if (b < 0x10) sb.append('0')
            sb.append(Integer.toHexString(b))
        }
        return sb.toString()
    }

    private fun toDec(bytes: ByteArray): Long {
        var result: Long = 0
        var factor: Long = 1
        for (i in bytes.indices) {
            val value = bytes[i].toLong() and 0xffL
            result += value * factor
            factor *= 256L
        }
        return result
    }

    private fun toReversedDec(bytes: ByteArray): Long {
        var result: Long = 0
        var factor: Long = 1
        for (i in bytes.indices.reversed()) {
            val value = bytes[i].toLong() and 0xffL
            result += value * factor
            factor *= 256L
        }
        return result
    }

    companion object {
        const val TAG = "nfc_test"
        // Replace this key with your desired Mifare Classic key
        val key = byteArrayOf(
            0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
            0x00.toByte(), 0x00.toByte(), 0x00.toByte()
        )
    }

    private fun getDefaultKeys(): List<ByteArray> {
        // Define the default keys for Mifare Classic cards

        return listOf(
            byteArrayOf(
                0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
                0xFF.toByte(), 0xFF.toByte()
            ),
            byteArrayOf(
                0xA0.toByte(), 0xA1.toByte(), 0xA2.toByte(), 0xA3.toByte(),
                0xA4.toByte(), 0xA5.toByte()
            ),
            byteArrayOf(
                0xB0.toByte(), 0xB1.toByte(), 0xB2.toByte(), 0xB3.toByte(),
                0xB4.toByte(), 0xB5.toByte()
            ),
            byteArrayOf(
                0xC0.toByte(), 0xC1.toByte(), 0xC2.toByte(), 0xC3.toByte(),
                0xC4.toByte(), 0xC5.toByte()
            ),
            byteArrayOf(
                0xD0.toByte(), 0xD1.toByte(), 0xD2.toByte(), 0xD3.toByte(),
                0xD4.toByte(), 0xD5.toByte()
            ),
            byteArrayOf(
                0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                0x00.toByte(), 0x00.toByte()
            ),
            byteArrayOf(
                0x01.toByte(), 0x01.toByte(), 0x01.toByte(), 0x01.toByte(),
                0x01.toByte(), 0x01.toByte()
            ),
            byteArrayOf(
                0x4D.toByte(), 0x3A.toByte(), 0x99.toByte(), 0xC3.toByte(),
                0x51.toByte(), 0xDD.toByte()
            ),
            byteArrayOf(
                0xA0.toByte(), 0xB0.toByte(), 0xC0.toByte(), 0xD0.toByte(),
                0xE0.toByte(), 0xF0.toByte()
            )
        )
    }
}
