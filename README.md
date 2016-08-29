# react-native-netpie-mqtt-auth-generator
React Native NETPIE Auth Module


```
import {NETPIE} from 'react-native-netpie-mqtt-auth-generator'
```
```


import io.cmmc.reactnative.netpieoauthauthen.RTCCMMCNetpieAuthPackage;  <---- Add This!

public class MainApplication extends Application implements ReactApplication {

    private final ReactNativeHost mReactNativeHost = new ReactNativeHost(this) {
        @Override
        protected boolean getUseDeveloperSupport() {
            return BuildConfig.DEBUG;
        }

        @Override
        protected List<ReactPackage> getPackages() {
            return Arrays.<ReactPackage>asList(
                    new MainReactPackage(),
                    new RTCCMMCNetpieAuthPackage() // <---- Add This!
            );
        }
    };

    @Override
    public ReactNativeHost getReactNativeHost() {
        return mReactNativeHost;
    }
}
```
