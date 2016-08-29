package io.cmmc.reactnative.netpieoauthauthen.microgear;

/**
 * Created by Nat on 8/29/16 AD.
 */
public class OAuthTokenModel {
    String oauth_token;
    String oauth_token_secret;

    public class OAuthAccessToken extends  OAuthTokenModel{
        String endpoint;
        String revoketoken;
    }

    public class OAuthRequestToken extends OAuthTokenModel {

    }
}


