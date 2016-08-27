package io.cmmc.reactnative.netpieoauthauthen.microgear;

import android.app.Activity;
import android.os.AsyncTask;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
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


public class OauthNetpieLibrary extends Activity {

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

    private static final String TAG = "NAT_NETPIE_OAUTH_NETPIE";
    OkHttpClient client;
    public String pathtowrite;
    public String authorize_callback;
    public static String _Key;
    public static String _Secret;
    public OAuth1_0a_Request request = new OAuth1_0a_Request();
    public String authorization;
    public JSONObject token_token_secret_json_object = new JSONObject();
    public static JSONObject file = new JSONObject();
    public static JSONObject file2 = new JSONObject();
    public static JSONObject file3 = new JSONObject();
    public static String End_point = "pie://gb.netpie.io:1883";
    public String name = "microgear.cache";
    public static SimpleTask simpleTask;
    public static Revoketoken rf;

    public String readJsonFromFile() throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader br;
        FileInputStream fis = new FileInputStream(pathtowrite);
        String line;
        br = new BufferedReader(new InputStreamReader(fis));
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        return sb.toString();
    }

    public String create(String appId, String appKey, String appSecret, String path) {
        client = new OkHttpClient.Builder()
                .addInterceptor(new LoggingInterceptor())
                .connectTimeout(3, TimeUnit.SECONDS)
                .writeTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .build();


        pathtowrite = path;
        authorize_callback = "scope=&appid=" + appId + "&mgrev=NJS1a&verifier=NJS1a";

        _Key = appKey;
        _Secret = appSecret;

        String keyNode;
        try {
            JSONObject json = new JSONObject(readJsonFromFile());
            keyNode = json.getJSONObject("_").getString("key");
            if (keyNode != null) {
                // no key node
                // then request oauth;
                authorization = request.OAuth(appKey, appSecret, authorize_callback);
                String str_result = requestOauthAndUpdateTokenObject("http://ga.netpie.io:8080/api/rtoken");

//                str_result = post("http://ga.netpie.io:8080/api/rtoken");
                Log.d(TAG, str_result);
                if (!keyNode.equals(appKey)) {
                    // always yes
                    if (str_result.equals("yes")) {
                        Log.d("NAT", "HIT: yes!");
                        rf = new Revoketoken();
                        rf.execute("http://ga.netpie.io:8080/api/revoke/");
                    }
                }

                return str_result;
            }
        } catch (FileNotFoundException e) {
            authorization = request.OAuth(appKey, appSecret, authorize_callback);
            requestOauthAndUpdateTokenObject("http://ga.netpie.io:8080/api/rtoken");
            saveTokenObjectToFile(token_token_secret_json_object);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }


        return "";
    }


    public void write(String fcontent) {
        FileWriter writer;
        try {
            writer = new FileWriter(pathtowrite);
            Log.i("path", pathtowrite);
            /** Saving the contents to the file*/
            writer.write(fcontent);
            /** Closing the writer object */
            writer.close();


        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String requestOauthAndUpdateTokenObject(String... params) {
        String response = post(params[0]);
        Log.d(TAG, "RESPONSE:: >> " + response);
        Log.d(TAG, "RESPONSE:: >> " + response);
        Log.d(TAG, "RESPONSE:: >> " + response);
        Log.d(TAG, "RESPONSE:: >> " + response);
        try {
            token_token_secret_json_object.put("", response);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return response;
    }


    String post(String url) {
//        RequestBody formBody = new FormBody.Builder()
//                .add("Authorization", authorization)
//                .build();
        RequestBody reqbody = RequestBody.create(null, new byte[0]);
        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", authorization)
                .post(reqbody)
                .build();
        try {
            Response response = client.newCall(request).execute();
            Log.d(TAG, "---->>> post: ");
            if (response.isSuccessful()) {
                token_token_secret_json_object.put("", response.body().string());
                Log.d(TAG, "-----> [YES]");
                return "yes";
            } else {
                Log.d(TAG, "-----> [ID]");
                return "secretandid";
            }
        } catch (IOException ex) {
            return "id";
        } catch (JSONException e) {
            e.printStackTrace();
            return "";
        }
    }

    public class SimpleTask extends AsyncTask<String, Void, JSONObject> {
        protected JSONObject doInBackground(String... params) {
            requestOauthAndUpdateTokenObject(params);
            return null;
        }
    }

    public class CheckInvalid extends AsyncTask<String, Void, String> {

        protected String doInBackground(String... params) {
            return requestOauthAndUpdateTokenObject(params);
        }
    }


    public class Revoketoken extends AsyncTask<String, Void, JSONObject> {
        public String token, revokecode;

        protected JSONObject doInBackground(String... params) {
            ReadFile();
            URL Url;
            revokecode = revokecode.replaceAll("/", "_");
            try {
                Url = new URL(params[0] + token + "/" + revokecode);
                URLConnection conn = Url.openConnection();
                InputStream re = conn.getInputStream();
                BufferedReader rd = new BufferedReader(new InputStreamReader(re));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = rd.readLine()) != null) {
                    response.append(line);
                }
                rd.close();
                Log.d(TAG, response + "");
            } catch (IOException e) {
                e.printStackTrace();
            }
            return null;
        }

        public String ReadFile() {
            try {
                JSONObject json = new JSONObject(readJsonFromFile());
                JSONObject rootNode = json.getJSONObject("_");
                JSONObject accessTokenNode = rootNode.getJSONObject("accesstoken");
                token = accessTokenNode.getString("token");
                revokecode = accessTokenNode.getString("revokecode");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (JSONException e) {
                e.printStackTrace();
            }
            return token;
        }
    }

    public static Map<String, String> splitQuery_Request(JSONObject request_token) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        String[] pairs = request_token.toString().split("&");
        int i = 0;
        for (String pair : pairs) {
            int idxs = pair.indexOf("o");
            int idxe = pair.indexOf("=");
            if (i == 2) {
                query_pairs.put(pair.substring(idxs, idxe), pair.substring(idxe + 1, pair.length() - 2));
            } else {
                query_pairs.put(pair.substring(idxs, idxe), pair.substring(idxe + 1));
            }
            i++;
        }
        return query_pairs;
    }

    public static Map<String, String> splitQuery_Access(JSONObject request_token) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap<String, String>();
        String[] pairs = request_token.toString().split("&");
        int i = 0;
        for (String pair : pairs) {
            int idxs = pair.indexOf("o");
            int idxe = pair.indexOf("=");
            if (i == 3) {
                query_pairs.put(pair.substring(idxs, idxe), pair.substring(idxe + 1, pair.length() - 2));
            } else if (i != 0) {
                query_pairs.put(pair.substring(idxs, idxe), pair.substring(idxe + 1));
            }
            i++;
        }
        return query_pairs;
    }

    public void saveTokenObjectToFile(JSONObject Request_token) { //token_token_secret_json_object
        Map<String, String> request;
        Map<String, String> access;
        try {
            request = splitQuery_Request(Request_token);
            String request_token = request.get("oauth_token");
            String request_token_secret = request.get("oauth_token_secret");
            JSONObject Request_Access_token = new OAuth1_0a_Access().OAuth(_Key, _Secret, request_token,
                    request_token_secret);
            access = splitQuery_Access(Request_Access_token);
            String access_token = access.get("oauth_token");
            String access_token_secret = access.get("oauth_token_secret");
            String revoketoken = Signature(_Secret, access_token_secret, access_token);
            file.putOpt("key", _Key);
            file.put("requesttoken", "null");
            file2.put("token", access_token);
            file2.put("secret", access_token_secret);
            file2.put("endpoint", End_point);
            file2.put("revokecode", revoketoken);
            file.put("accesstoken", file2);
            file3.put("_", file);
            String g = file3.toString();
            String f = g.replace("\\/", "/");
            write(f);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        }
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


}
