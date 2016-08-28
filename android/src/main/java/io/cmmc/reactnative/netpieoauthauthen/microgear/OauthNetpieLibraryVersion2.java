package io.cmmc.reactnative.netpieoauthauthen.microgear;

import android.content.Context;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by Nat on 8/27/16 AD.
 */
public class OauthNetpieLibraryVersion2 {

    private String mOauth_request_token;
    private String mOauth_request_token_secret;

    public interface RequestNetpieCallback {
        public void onFinished(String result, String token);
    }

    private static final String TAG = "OauthNetpieLibV2";
    private OkHttpClient client;
    private String authorize_callback;
    private Context mContext;

    private String mAppId;
    private String mAppKey;
    private String mAppSecret;
    private String mAuthorization;
    private OAuth1_0a_Request mOAuthRequest;

    class LoggingInterceptor implements Interceptor {
        @Override
        public Response intercept(Interceptor.Chain chain) throws IOException {
            Request request = chain.request();

            long t1 = System.nanoTime();
            Log.i(TAG, String.format("Sending request %s on %s%n%s",
                    request.url(), chain.connection(), request.headers()));

            Response response = chain.proceed(request);

            long t2 = System.nanoTime();
            Log.d(TAG, String.format("Received response for %s in %.1fms%n%s",
                    response.request().url(), (t2 - t1) / 1e6d, response.headers()));

            return response;
        }
    }


    public OauthNetpieLibraryVersion2(Context context) {
        super();
        mContext = context;
        mOAuthRequest = new OAuth1_0a_Request();
        client = new OkHttpClient.Builder()
//                .addInterceptor(new LoggingInterceptor())
                .connectTimeout(3, TimeUnit.SECONDS)
                .writeTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .build();
    }

    public String create(String appId, String appKey, String appSecret, final String path) {
        mAppId = appId;
        mAppKey = appKey;
        mAppSecret = appSecret;
        authorize_callback = "scope=&appid=" + appId + "&mgrev=NJS1a&verifier=NJS1a";

        if (AppHelper.isFirstRun(mContext)) {
            mAuthorization = mOAuthRequest.OAuth(appKey, appSecret, authorize_callback);
            Log.d(TAG, "[create: ] authorization => " + mAuthorization);
            sendPostRequestToNetpie("http://ga.netpie.io:8080/api/rtoken",
                    mAuthorization, new RequestNetpieCallback() {
                        @Override
                        public void onFinished(String result, String token) {
                            Log.d(TAG, "onFinished: => " + result);
                            Log.d(TAG, "Token : => " + token);
                            if (!token.isEmpty()) {
                                updateOAuthRequestToken(token);
                                updateOAuthAccessToken();
                            }
                        }
                    });
        } else {

        }
        return "String";
    }

    private void updateOAuthAccessToken() {
        JSONObject Request_Access_token = new OAuth1_0a_Access().OAuth(mAppKey, mAppSecret,
                mOauth_request_token, mOauth_request_token_secret);

        try {
            String oauth_acess_token_string = Request_Access_token.get("").toString();
            Log.d(TAG, "[ACCESS TOKEN STRING] onFinished: = " + oauth_acess_token_string);
            Map<String, String> access = processToken(oauth_acess_token_string);
            Log.d(TAG, "onFinished: [ACCESS TOKEN RESP] " + access.toString());

            String access_token = access.get("oauth_token");
            String access_token_secret = access.get("oauth_token_secret");
            String revoketoken = Signature(mAppSecret, access_token_secret, access_token);

            Log.d(TAG, "access_token: " + access_token);
            Log.d(TAG, "access_token_secret: " + access_token_secret);
            Log.d(TAG, "revoketoken: " + revoketoken);
            Log.d(TAG, "processToken: [OAuth Access]" + Request_Access_token.toString());

        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private void updateOAuthRequestToken(String token) {
        Map<String, String> query_pairs = processToken(token);
        mOauth_request_token = query_pairs.get("oauth_token");
        mOauth_request_token_secret = query_pairs.get("oauth_token_secret");
    }


    public static String Signature(String consumerSecret, String access_token_secret, String access_token) {
        String key = access_token_secret + "&" + consumerSecret;
        String hash = "";
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "HmacSHA1");
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(keySpec);
            byte[] result = mac.doFinal(access_token.getBytes());
            hash = Base64.encode(result);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return hash.toString();

    }

    private Map<String, String> processToken(String request_token) {
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        String[] pairs = request_token.split("&");
        Log.d(TAG, "[1] processToken: " + pairs.toString());
        int i = 0;
        for (String pair : pairs) {
            String[] o = pair.split("=");
            query_pairs.put(o[0], o[1]);
        }

        Log.d(TAG, "processToken: " + query_pairs.toString());

        return query_pairs;

    }

    void sendPostRequestToNetpie(String url, String authorization, RequestNetpieCallback callback) {
        RequestBody reqbody = RequestBody.create(null, new byte[0]);
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", authorization)
                .post(reqbody)
                .build();
        try {
            Response response = client.newCall(request).execute();
            Log.d(TAG, "---->>> sendPostRequestToNetpie: [RESPONSE] -> ");
            if (response.isSuccessful()) {
                Log.d(TAG, "-----> [YES]");
                callback.onFinished("yes", response.body().string());
            } else {
                callback.onFinished("secretandid", "");
            }
        } catch (IOException ex) {
            callback.onFinished("id", "");
        }
    }
}
