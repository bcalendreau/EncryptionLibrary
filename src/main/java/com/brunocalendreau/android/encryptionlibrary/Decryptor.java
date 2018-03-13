package com.brunocalendreau.android.encryptionlibrary;

import android.app.LauncherActivity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor {

    private static final String TAG = Decryptor.class.getSimpleName();

    private static final String AES_MODE_API23 = "AES/GCM/NoPadding";
    private static final String AES_MODE_OLD = "AES/ECB/PKCS7Padding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static final String ENCRYPTED_KEY = "Encrypted_AES";
    private static KeyStore keyStore;

    static {
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        } catch (Exception e) {
            Log.e(TAG, "Error loading keyStore");
            e.printStackTrace();
        }
    }

    private Context ctx;
    private SharedPreferences sp;

    /*
     *  @param SharedPreferences = used for API < 23 to store encrypted AES Key
     */
    public Decryptor(Context ctx, @Nullable SharedPreferences sp) {
        this.ctx = ctx;
        this.sp = sp;
    }

    static byte[] rsaDecrypt(final String alias, byte[] encrypted) throws Exception {

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);

        //Decrypt  the text
        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(encrypted), output);

        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }
        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i);
        }
        cipherInputStream.close();

        return bytes;
    }

    public byte[] decryptData(final String alias, final String encryptedData, final String encryptedIV)
            throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
            NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        Cipher cipher = null;
        byte[] decoded = Base64.decode(encryptedData.getBytes(), Base64.DEFAULT);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cipher = Cipher.getInstance(AES_MODE_API23);
                byte[] iv = Base64.decode(encryptedIV, Base64.DEFAULT);
                final GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias), spec);
            } else {
                cipher = Cipher.getInstance(AES_MODE_OLD, "BC");
                cipher.init(Cipher.DECRYPT_MODE, getSecretKey(alias));
            }
        } catch (Exception e) {
            Log.e(TAG, "Can't get key");
            e.printStackTrace();
            //Going back to Login !
            Intent intent = new Intent(ctx, LauncherActivity.class);
            intent.putExtra("ACTIVITY", TAG);
            ctx.startActivity(intent);
        }

        return cipher.doFinal(decoded);

    }

    private SecretKey getSecretKey(final String alias) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return (SecretKey) keyStore.getKey(alias, null);
        } else {
            if (sp == null) {
                throw new RuntimeException("You must pass a SharedPreferences object in constructor for API < 23");
            }
            String encryptedKeyB64 = sp.getString(ENCRYPTED_KEY, null);
            if (encryptedKeyB64 == null) {
                Log.d(TAG, "Can't find the AES key");
                return null;
            }
            byte[] encryptedKey = Base64.decode(encryptedKeyB64, Base64.DEFAULT);
            byte[] key = rsaDecrypt(alias, encryptedKey);
            return new SecretKeySpec(key, "AES");
        }
    }
}