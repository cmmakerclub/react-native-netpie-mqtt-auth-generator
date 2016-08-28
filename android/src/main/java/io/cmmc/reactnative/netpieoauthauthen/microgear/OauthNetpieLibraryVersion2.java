package io.cmmc.reactnative.netpieoauthauthen.microgear;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by Nat on 8/27/16 AD.
 */
public class OauthNetpieLibraryVersion2 {
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
                .addInterceptor(new LoggingInterceptor())
                .connectTimeout(3, TimeUnit.SECONDS)
                .writeTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .build();
    }

    public String create(String appId, String appKey, String appSecret, String path) {
        mAppId = appId;
        mAppKey = appKey;
        mAppSecret = appSecret;
        authorize_callback = "scope=&appid=" + appId + "&mgrev=NJS1a&verifier=NJS1a";

        if (AppHelper.isFirstRun(mContext)) {
            mAuthorization = mOAuthRequest.OAuth(appKey, appSecret, authorize_callback);
            String str_result = sendPostRequestToNetpie("http://ga.netpie.io:8080/api/rtoken", mAuthorization);
            Log.d(TAG, ">>>> " + str_result);
            /* AppHelper.setFirstRun(mContext, false); */
        } else {

        }
        return "String";
    }

    String sendPostRequestToNetpie(String url, String authorization) {
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
                Log.d(TAG, response.body().string());
                Log.d(TAG, "-----> [YES]");
                return "yes";
            } else {
                return "secretandid";
            }
        } catch (IOException ex) {
            return "id";
        }
    }
}
