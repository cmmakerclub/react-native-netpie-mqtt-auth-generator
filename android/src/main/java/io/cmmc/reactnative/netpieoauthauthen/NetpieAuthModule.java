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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.cmmc.reactnative.netpieoauthauthen.microgear.Base64;
import io.cmmc.reactnative.netpieoauthauthen.microgear.OauthNetpieLibrary;

/**
 * Created by Nat on 8/26/16 AD.
 */
public class NetpieAuthModule extends ReactContextBaseJavaModule {
    public ReactApplicationContext mContext;
    public static final String TAG = NetpieAuthModule.class.getSimpleName();

    public OauthNetpieLibrary oauthNetpieLibrary;

    public String name = "microgear.cache";
    public File tempFile;
    public File cDir;
    public Context context;

    public String appid = "CMMC";
    public String appkey = "60qturoh80sRMXq";
    public String appsecret = "ahKOgQWSE6h87Anc9QP5HJgdQ";

    private String mqttuser, mqttclientid, mqttpassword;

    public NetpieAuthModule(ReactApplicationContext reactContext) {
        super(reactContext);
        mContext = reactContext;
        context = reactContext.getApplicationContext();
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

        oauthNetpieLibrary = new OauthNetpieLibrary();
        cDir = context.getCacheDir();
        tempFile = new File(cDir.getPath() + "/" + name);
        String a = oauthNetpieLibrary.create(appid, appkey, appsecret, tempFile.toString());

        if (a.equals("yes")) {
            Log.d(TAG, "config: YES");
            brokerconnect(appsecret);
            WritableMap params = new WritableNativeMap();
            params.putString("appid", appid);
            params.putString("appkey", appkey);
            params.putString("appsecret", appsecret);
            params.putString("mqttusername", mqttuser);
            params.putString("mqttclientid", mqttclientid);
            params.putString("mqttpassword", mqttpassword);
            callback.invoke(false, params);
        } else if (a.equals("id")) {
            callback.invoke(true, "App id Invalid.");
            Log.d(TAG, "onCreate: App id Invalid");
        } else if (a.equals("secretandid")) {
            callback.invoke(true, "App id,Key or Secret Invalid.");
            Log.d(TAG, "onCreate: App id,Key or Secret Invalid");
        } else {
            callback.invoke(true, "Error: unknown reason.");
//            Log.d(TAG, "onCreate: App id,Key or Secret Invalid");
            //brokerconnect(appid, key, secret);
        }

    }

    private void brokerconnect(String secret) {
        File fi = new File(tempFile.toString());
        BufferedReader br;
        StringBuilder sb = new StringBuilder();
        String line;
        String secrettoken, secretid, hkey, ckappkey;
        FileInputStream fis;
        try {
            fis = new FileInputStream(tempFile.toString());
            br = new BufferedReader(new InputStreamReader(fis));
            while ((line = br.readLine()) != null) {
                System.out.print(line);
                sb.append(line);
            }
            Log.d(TAG, "NAT: " + sb.toString());
            JSONObject json = new JSONObject(sb.toString());
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

        } catch (FileNotFoundException e) {

        } catch (JSONException | IOException e) {
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
