package de.adorsys.android.securestoragelibrary;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import com.yakivmospan.scytale.Crypto;
import com.yakivmospan.scytale.Options;
import com.yakivmospan.scytale.Store;

import java.security.KeyPair;

import javax.crypto.SecretKey;

class KeystoreTool {
    private static final String KEY_ALIAS = "d_key_store";

    @Nullable
    static String encryptMessage(@NonNull Context context, @NonNull String plainMessage) {
        Store store = new Store(context.getApplicationContext());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            SecretKey key;
            if(!store.hasKey(KEY_ALIAS)) {
                key = store.generateSymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            } else {
                key = store.getSymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            }

            Crypto crypto = new Crypto(Options.TRANSFORMATION_SYMMETRIC);
            return crypto.encrypt(plainMessage, key);
        } else {
            KeyPair keyPair;
            if(!store.hasKey(KEY_ALIAS)) {
                keyPair = store.generateAsymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            } else {
                keyPair = store.getAsymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            }
            Crypto crypto = new Crypto(Options.TRANSFORMATION_ASYMMETRIC);
            return crypto.encrypt(plainMessage, keyPair);
        }
    }

    @Nullable
    static String decryptMessage(@NonNull Context context, @NonNull String encryptedMessage) {
        Store store = new Store(context.getApplicationContext());
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            SecretKey key;
            if(!store.hasKey(KEY_ALIAS)) {
                key = store.generateSymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            } else {
                key = store.getSymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            }

            Crypto crypto = new Crypto(Options.TRANSFORMATION_SYMMETRIC);
            return crypto.decrypt(encryptedMessage, key);
        } else {
            KeyPair keyPair;
            if(!store.hasKey(KEY_ALIAS)) {
                keyPair = store.generateAsymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            } else {
                keyPair = store.getAsymmetricKey(KEY_ALIAS, KeystoreTool.class.getPackage().getName().toCharArray());
            }
            Crypto crypto = new Crypto(Options.TRANSFORMATION_ASYMMETRIC);
            return crypto.decrypt(encryptedMessage, keyPair);
        }
    }

    public static boolean keyPairExists(@NonNull Context context) {
        Store store = new Store(context.getApplicationContext());
        return store.hasKey(KEY_ALIAS);
    }

    public static void deleteKeyPair(@NonNull Context context) {
        Store store = new Store(context.getApplicationContext());
        store.deleteKey(KEY_ALIAS);
    }
}