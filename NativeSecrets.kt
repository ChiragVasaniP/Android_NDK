package com.app.example

import android.content.Context
import android.os.Build
import android.util.Log
import com.app.jungle.journey.adventure.shared.base.viewbase.AdvancedBaseActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException

object NativeSecrets {
    init {
        System.loadLibrary("secureapi")
    }

    external fun getServerUrl(context: Context = Controller.instance): String
    external fun getGeneralUrl(context: Context = Controller.instance): String
    external fun getDecryptKey(context: Context = Controller.instance): String
    external fun isFridaRunning(context: Context = Controller.instance): Boolean
    external fun isDeviceRooted(context: Context = Controller.instance): Boolean
    external fun isDebuggerAttached(context: Context = Controller.instance): Boolean
    external fun isAdbOrDevModeEnabled(context: Context, deviceId: String): Boolean


    @JvmStatic
    fun onTamperingDetected() {
        val activity = Controller.foregroundActivity
        activity.runOnUiThread {
            activity.onTamperingDetected()
        }
    }

    @JvmStatic
    fun generateStableDeviceId(): String {
        val deviceInfo = Build.BOARD +
                Build.BRAND +
                Build.DEVICE +
                Build.DISPLAY +
                Build.HOST +
                Build.ID +
                Build.MANUFACTURER +
                Build.MODEL +
                Build.PRODUCT +
                Build.TAGS +
                Build.TYPE +
                Build.USER +
                Build.FINGERPRINT

        return deviceInfo.hashCode().toString()
    }


}