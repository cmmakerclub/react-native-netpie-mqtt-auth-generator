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

import io.cmmc.reactnative.netpieoauthauthen.NetpieAuthModule;
import io.cmmc.reactnative.netpieoauthauthen.utils.LoggingInterceptor;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;


/**
 * Created by Nat on 8/27/16 AD.
 */
public class OauthNetpieLibraryVersion2 {
    private static final String TAG = "OauthNetpieLibV2";
    private OkHttpClient okHttpClient;
    private Context mContext;

    private String mAppId;
    private String mAppKey;
    private String mAppSecret;
    private String mAuthorization;

    private OAuth1_0a_Request mOAuthRequest;
    private OAuthAccessToken mOAuthAccessToken;

    private JSONObject mJSONTokenObject;

    public OauthNetpieLibraryVersion2(Context context) {
        super();
        mContext = context;
        mJSONTokenObject = new JSONObject();
        mOAuthRequest = new OAuth1_0a_Request();
        okHttpClient = new OkHttpClient.Builder()
                .addInterceptor(new LoggingInterceptor())
                .connectTimeout(3, TimeUnit.SECONDS)
                .writeTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .build();
    }

    public String create(String appId, String appKey, String appSecret, NetpieAuthModule.NetpieAuthCallback authCallback) {
        mAppId = appId;
        mAppKey = appKey;
        mAppSecret = appSecret;
        String _result = "";
        if (!AppHelper.isMicroGearCached(mContext)) {
            fetchAndSaveMicroGear(mAppId, mAppKey, mAppSecret, authCallback);
        } else {
            restoreAccessTokenFromCache();
            String cachedKey = getAppKeyFromCache();
            //Log.d(TAG, "FOUND CACHED MICROGEAR: appKey => " + mAppKey);
            if (cachedKey.equals(mAppKey)) {
                //Log.d(TAG, "[VALID APP KEY] ");
                authCallback.onFinished("yes");
            } else {
                //Log.d(TAG, "[DIFFERENT APP KEY] REVOKE THE CACHED KEY..");
                revokeAccessToken(mOAuthAccessToken, authCallback);
            }
        }
        return _result;
    }

    private void fetchAndSaveMicroGear(final String appId, final String appKey,
                                       final String appSecret,
                                       final NetpieAuthModule.NetpieAuthCallback authCallback) {
        String authorizationCallback = "scope=&appid=" + appId + "&mgrev=NJS1a&verifier=NJS1a";
        mAuthorization = mOAuthRequest.OAuth(appKey, appSecret, authorizationCallback);
        sendPostRequestToNetpie("http://ga.netpie.io:8080/api/rtoken",
                mAuthorization, new RequestNetpieCallback() {
                    @Override
                    public void onFinished(String result, String token) {
                        // result = "yes"
                        if (!token.isEmpty()) {
                            OAuthRequestToken _oAuthRequestToken = parseOAuthRequestTokenString(token);
                            mOAuthAccessToken = getOAuthSecretToken(appKey,
                                    appSecret, _oAuthRequestToken);
                            saveAllOAuthToken(mOAuthAccessToken, appKey);
                            AppHelper.cacheMicroGearToken(mContext, true);
                        }
                        authCallback.onFinished(result);
                    }
                });
    }

    private void restoreAccessTokenFromCache() {
        // TODO: fill the object with all values.
        mOAuthAccessToken = new OAuthAccessToken();
        mOAuthAccessToken.revoketoken = getAccessTokenFromCache("revokecode");
        mOAuthAccessToken.oauth_token = getAccessTokenFromCache("token");
    }

    private JSONObject getJsonObjectFromCache() {
        JSONObject obj = null;
        try {
            obj = new JSONObject(AppHelper.getString(mContext, Constants.MICROGEAR_CACHE, "{}"));
            Log.d(TAG, "create: [PARSED JSON OBJECT]" + obj.toString());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return obj;
    }

    private String getAppKeyFromCache() {
        JSONObject jsonObject = getJsonObjectFromCache();
        String cachedKey = "";
        try {
            cachedKey = jsonObject.getJSONObject("_").getString("key");
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return cachedKey;
    }

    private String getAccessTokenFromCache(String key) {
        String ret = "";
        try {
            JSONObject accessToken = getJsonObjectFromCache().getJSONObject("_").
                    getJSONObject("accesstoken");
            ret = accessToken.getString(key);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return ret;
    }

    private void revokeAccessToken(OAuthAccessToken oAuthAccessToken,
                                   final NetpieAuthModule.NetpieAuthCallback authCallback) {
        String url = String.format("http://ga.netpie.io:8080/api/revoke/%s/%s",
                oAuthAccessToken.oauth_token, oAuthAccessToken.revoketoken);

        url = url.replace("\\/", "/");

        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();
        okHttpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.d(TAG, "onFailure: ");
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                Log.d(TAG, "onResponse: " + response.body().string());
                AppHelper.setString(mContext, Constants.MICROGEAR_CACHE, "{}");
                AppHelper.cacheMicroGearToken(mContext, false);
                fetchAndSaveMicroGear(mAppId, mAppKey, mAppSecret, authCallback);
            }
        });
    }

    private void saveAllOAuthToken(OAuthAccessToken oAuthAccessToken, String appKey) {
        JSONObject underscoreNode = new JSONObject();
        JSONObject accessTokenChild = new JSONObject();
        try {
            accessTokenChild.put("token", oAuthAccessToken.oauth_token);
            accessTokenChild.put("secret", oAuthAccessToken.oauth_token_secret);
            accessTokenChild.put("endpoint", oAuthAccessToken.endpoint);
            accessTokenChild.put("revokecode", oAuthAccessToken.revoketoken);
            underscoreNode.putOpt("key", appKey);
            underscoreNode.put("requesttoken", "null");
            underscoreNode.put("accesstoken", accessTokenChild);
            mJSONTokenObject.put("_", underscoreNode);

            AppHelper.setString(mContext, Constants.MICROGEAR_CACHE, mJSONTokenObject.toString());

        } catch (JSONException e) {
            e.printStackTrace();
        }

    }

    private OAuthAccessToken getOAuthSecretToken(String appKey, String appSecret,
                                                 OAuthRequestToken oAuthRequestToken) {
        JSONObject Request_Access_token = new OAuth1_0a_Access().OAuth(appKey, appSecret,
                oAuthRequestToken.oauth_token, oAuthRequestToken.oauth_token_secret);
        final OAuthAccessToken _oAuthAccessToken = new OAuthAccessToken();

        try {
            String oauth_acess_token_string = Request_Access_token.get("").toString();
            Map<String, String> access = processToken(oauth_acess_token_string);

            _oAuthAccessToken.oauth_token = access.get("oauth_token");
            _oAuthAccessToken.oauth_token_secret = access.get("oauth_token_secret");
            _oAuthAccessToken.endpoint = access.get("endpoint");

            //reference copy
            String accessTokenSecret = _oAuthAccessToken.oauth_token_secret;
            String accessToken = _oAuthAccessToken.oauth_token;

            _oAuthAccessToken.revoketoken = Signature(appSecret, accessTokenSecret, accessToken);

        } catch (JSONException e) {
            e.printStackTrace();
        }

        return _oAuthAccessToken;
    }

    private OAuthRequestToken parseOAuthRequestTokenString(String token) {
        Map<String, String> query_pairs = processToken(token);
        OAuthRequestToken _oAuthRequestToken = new OAuthRequestToken();

        _oAuthRequestToken.oauth_token = query_pairs.get("oauth_token");
        _oAuthRequestToken.oauth_token_secret = query_pairs.get("oauth_token_secret");

        return _oAuthRequestToken;
    }


    public static String Signature(String consumerSecret, String access_token_secret,
                                   String access_token) {
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
            Response response = okHttpClient.newCall(request).execute();
            if (response.isSuccessful()) {
                callback.onFinished("yes", response.body().string());
            } else {
                callback.onFinished("secretandid", "");
            }
        } catch (IOException ex) {
            callback.onFinished("id", "");
        }
    }
    /*
        InnerClass
     */

    public interface RequestNetpieCallback {
        public void onFinished(String result, String token);
    }

    public static class OAuthRequestToken {
        String oauth_token;
        String oauth_token_secret;
    }

    public class OAuthAccessToken extends OAuthRequestToken {
        String endpoint;
        String revoketoken;
    }
}
