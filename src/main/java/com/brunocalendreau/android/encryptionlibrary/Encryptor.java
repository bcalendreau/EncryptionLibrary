package com.brunocalendreau.android.encryptionlibrary;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class Encryptor {

    private static final String AES_MODE_API23 = "AES/GCM/NoPadding";
    private static final String AES_MODE_OLD = "AES/ECB/PKCS7Padding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static final String PREFERENCES_ENCRYPTED_KEY = "Encrypted_AES";

    private static final String TAG = Encryptor.class.getSimpleName();

    private Context ctx;
    private KeyStore keyStore;
    private SharedPreferences sp = null;

    private byte[] iv;

    /*
     *   @param SharedPreferences = used for API < 23 to store encrypted AES Key
     */
    public Encryptor(Context ctx, @Nullable SharedPreferences sp) {
        this.ctx = ctx;
        this.sp = sp;
        try {
            keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
        } catch (Exception e) {
            Log.e(TAG, "Error loading KeyStore");
            e.printStackTrace();
        }
    }

    public String encryptText(final String alias, final byte[] textToEncrypt) throws Exception {

        Cipher cipher;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(AES_MODE_API23);
        } else {
            cipher = Cipher.getInstance(AES_MODE_OLD, "BC");
        }

        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(alias));
        iv = cipher.getIV();

        byte[] encodedBytes = cipher.doFinal(textToEncrypt);

        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }

    /* Method that returns a key to encrypt
            @param alias : the alias used to store and get the key
            @return Key : the AES Key
     */
    @NonNull
    private Key getSecretKey(final String alias) {

        Key key = null;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!keyStore.containsAlias(alias)) {

                    Log.d(TAG, "Building KEY new version");
                    KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

                    keyGenerator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build());

                    key = keyGenerator.generateKey();
                } else {
                    Log.d(TAG, "Retrieving key");
                    key = keyStore.getKey(alias, null);
                }

            } else {
                Log.d(TAG, "Building KEY old version");

                // Create new keys if needed
                if (!keyStore.containsAlias(alias) || keyStore.getCertificate(alias).getPublicKey() == null) {
                    generateRSAkeys(alias);
                }
                if (sp == null) {
                    throw new RuntimeException("You must pass a SharedPreferences object in constructor for API < 23");
                }
                String encryptedKeyB64 = sp.getString(PREFERENCES_ENCRYPTED_KEY, null);
                // If no key, create a new AES one
                if (encryptedKeyB64 == null || encryptedKeyB64.length() == 0) {
                    Log.d(TAG, "Generating new key with RSA keys");
                    byte[] aesKey = new byte[16];
                    SecureRandom secureRandom = new SecureRandom();
                    secureRandom.nextBytes(aesKey);
                    key = new SecretKeySpec(aesKey, "AES");
                    byte[] encryptedKey = rsaEncrypt(alias, aesKey);
                    encryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
                    SharedPreferences.Editor edit = sp.edit();
                    edit.putString(PREFERENCES_ENCRYPTED_KEY, encryptedKeyB64);
                    edit.apply();
                } else {
                    byte[] encryptedKey = Base64.decode(encryptedKeyB64, Base64.DEFAULT);
                    byte[] keydecrypt = Decryptor.rsaDecrypt(alias, encryptedKey);
                    key = new SecretKeySpec(keydecrypt, "AES");
                }
            }

            if (key == null) {
                throw new RuntimeException("Key generator returned null");
            }
        } catch (Exception e) {
            Log.d(TAG, "Couldn't get the AES Key");
            e.printStackTrace();
        }
        return key;
    }

    private void generateRSAkeys(final String alias) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {

        Log.d(TAG, "Generating RSA keys");
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 30);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);
        generator.initialize(spec);
        generator.generateKeyPair();
    }

    private byte[] rsaEncrypt(final String alias, byte[] secret) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);

        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);

        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    public String getIv() {
        if (iv == null || iv.length == 0) {
            return null;
        }
        return Base64.encodeToString(iv, Base64.DEFAULT);
    }
}
