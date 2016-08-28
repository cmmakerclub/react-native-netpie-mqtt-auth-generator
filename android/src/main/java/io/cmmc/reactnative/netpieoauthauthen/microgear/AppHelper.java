package io.cmmc.reactnative.netpieoauthauthen.microgear;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.support.v4.widget.SwipeRefreshLayout;
import android.view.View;

import java.lang.reflect.Field;
import java.util.Calendar;
import java.util.Date;

public class AppHelper {
    private static boolean male;
    public static final String TAG = AppHelper.class.getSimpleName();

    public static SharedPreferences getSharedPreference(Context context) {
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);
        return mSharedPref;
    }

    public static boolean setString(Context context, String key, String value) {
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);

        SharedPreferences.Editor editor = mSharedPref.edit();

        editor.putString(key, value);
        return editor.commit();
    }

    public static boolean setBoolean(Context context, String key, boolean value) {
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);

        SharedPreferences.Editor editor = mSharedPref.edit();

        editor.putBoolean(key, value);
        return editor.commit();
    }


    public static boolean getBoolean(Context context, String key, boolean fallback) {
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);


        return mSharedPref.getBoolean(key, fallback);
    }

    public static View getRootView(Activity act) {
        return act.findViewById(android.R.id.content);
    }

    public static String getString(Context context, String key) {
        final String fallback = "";
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);


        return mSharedPref.getString(key, fallback);
    }

    public static String getString(Context context, String key, String fallback) {
        SharedPreferences mSharedPref = context.getSharedPreferences(Constants.APP_PREF,
                Context.MODE_PRIVATE);


        return mSharedPref.getString(key, fallback);
    }


    public static boolean xset(Object object, String fieldName, Object fieldValue) {
        Class<?> clazz = object.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                field.set(object, fieldValue);
                return true;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    public static <E> E get(Object object, String fieldName) {
        Class<?> clazz = object.getClass();
        while (clazz != null) {
            try {
                Field field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return (E) field.get(object);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return null;
    }

    public static Calendar getCalendarFromDate(Date d) {
        Calendar c = Calendar.getInstance();
        c.setTime(d);
        return c;
    }


    public static boolean isMicroGearCached(Context context) {
        SharedPreferences sp = AppHelper.getSharedPreference(context);
        boolean status = sp.getBoolean(Constants.RUN_FIRST_TIME, true);

        return status;
    }


    public static void setSwipeViewRefreshing(final SwipeRefreshLayout mSwipeLayout, final boolean enabled) {
        mSwipeLayout.post(new Runnable() {
            @Override
            public void run() {
                mSwipeLayout.setRefreshing(enabled);
            }
        });

    }

    public static boolean cacheMicroGearToken(Context context, boolean b) {
        return AppHelper.setBoolean(context, Constants.RUN_FIRST_TIME, b);
    }


    public static int getAppVersion(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(context.getPackageName(), 0);
            return packageInfo.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            // should never happen
            throw new RuntimeException("Could not get package name: " + e);
        }
    }

    public static void setGCMToken(String GCMToken) {

    }

}

