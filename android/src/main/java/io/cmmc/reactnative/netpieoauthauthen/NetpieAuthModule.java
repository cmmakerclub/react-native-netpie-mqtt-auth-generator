package io.cmmc.reactnative.netpieoauthauthen;

import android.content.Context;
import android.support.annotation.Nullable;
import android.util.Log;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.cmmc.reactnative.netpieoauthauthen.microgear.AppHelper;
import io.cmmc.reactnative.netpieoauthauthen.microgear.Base64;
import io.cmmc.reactnative.netpieoauthauthen.microgear.Constants;
import io.cmmc.reactnative.netpieoauthauthen.microgear.OauthNetpieLibraryVersion2;

/**
 * Created by Nat on 8/26/16 AD.
 */
public class NetpieAuthModule extends ReactContextBaseJavaModule {
    public ReactApplicationContext mContext;
    public static final String TAG = NetpieAuthModule.class.getSimpleName();

    public OauthNetpieLibraryVersion2 oauthNetpieLibrary;

    public String name = "microgear.cache";
    public File tempFile;
    public File cDir;
    public Context context;

    public String appid = "CMMC";
    public String appkey = "60qturoh80sRMXq";
    public String appsecret = "ahKOgQWSE6h87Anc9QP5HJgdQ";

    private String mqttuser, mqttclientid, mqttpassword;

    public interface NetpieAuthCallback {
        public void onFinished(String result);
    }

    public NetpieAuthModule(ReactApplicationContext reactContext) {
        super(reactContext);
        mContext = reactContext;
        context = reactContext.getApplicationContext();
        oauthNetpieLibrary = new OauthNetpieLibraryVersion2(mContext);
    }

    @Override
    public String getName() {
        return "NetpieAuthModule";
    }

    private void sendEvent(ReactContext reactContext,
                           String eventName,
                           @Nullable Object params) {
        reactContext
                .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit(eventName, params);
    }

    @ReactMethod
    public String testReactMethod() {
        return "hello";
    }

    @ReactMethod
    public void config(ReadableMap configMap, final Callback callback) {
        String _appId = configMap.getString("appId");
        String _appKey = configMap.getString("appKey");
        String _appSecret = configMap.getString("appSecret");

        appid = _appId;
        appkey = _appKey;
        appsecret = _appSecret;

        cDir = context.getCacheDir();
        tempFile = new File(cDir.getPath() + "/" + name);

        oauthNetpieLibrary.create(appid, appkey, appsecret, new NetpieAuthCallback() {
            @Override
            public void onFinished(String result) {
                Log.d(TAG, "onFinished: [RESULT] >> " + result);
                Log.d(TAG, "onFinished: [RESULT] >> " + result);
                Log.d(TAG, "onFinished: [RESULT] >> " + result);
                Log.d(TAG, "onFinished: [RESULT] >> " + result);

                if (result.equals("yes")) {
                    brokerconnect(appsecret);
                    Log.d(TAG, "[AUTH MODULE] config: YES");
                    WritableMap params = new WritableNativeMap();
                    params.putString("appid", appid);
                    params.putString("appkey", appkey);
                    params.putString("appsecret", appsecret);
                    params.putString("mqtt_username", mqttuser);
                    params.putString("mqtt_clientid", mqttclientid);
                    params.putString("mqtt_password", mqttpassword);
                    callback.invoke(false, params);
                } else if (result.equals("id")) {
                    callback.invoke(true, "App id Invalid.");
                    Log.d(TAG, "onCreate: App id Invalid");
                } else if (result.equals("secretandid")) {
                    callback.invoke(true, "App id,Key or Secret Invalid.");
                    Log.d(TAG, "onCreate: App id,Key or Secret Invalid");
                } else {
                    callback.invoke(true, "Error: unknown reason.");
                }
            }
        });

    }

    private void brokerconnect(String secret) {
        String secrettoken, secretid, hkey, ckappkey;
        JSONObject json = null;
        try {
            json = new JSONObject(AppHelper.getString(mContext, Constants.MICROGEAR_CACHE, "{}"));
            mqttuser = json.getJSONObject("_").getString("key");
            secrettoken = json.getJSONObject("_").getJSONObject("accesstoken").getString("secret");
            mqttclientid = json.getJSONObject("_").getJSONObject("accesstoken").getString("token");
            secretid = secret;
            hkey = secrettoken + "&" + secretid; //okay
            long date = new Date().getTime();
            date = date / 1000;
            mqttuser = mqttuser + "%" + date;
            SecretKeySpec keySpec = new SecretKeySpec(hkey.getBytes(), "HmacSHA1");
            try {
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(keySpec);
                mqttpassword = mqttclientid + "%" + mqttuser;
                byte[] result = mac.doFinal(mqttpassword.getBytes());
                mqttpassword = Base64.encode(result);
                Log.d(TAG, "brokerconnect: >>> ");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    @ReactMethod
    public void writeBackTest() {
        WritableMap params = new WritableNativeMap();
        params.putString("topic_key", "topic_value");
        sendEvent(mContext, "messageArrived", params);
    }

}
