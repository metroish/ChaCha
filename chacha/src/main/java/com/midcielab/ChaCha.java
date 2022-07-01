package com.midcielab;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha - simple implementation of file encryption/decryption with
 * ChaCha20-Poly1305
 */
public class ChaCha {

    private static final int KEY_ITERATION = 90001;
    private static final int KEY_BIT_LENGTH = 256;
    private static final int NONCE_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 32;
    private static final String ALGORITHM_STRING = "ChaCha20-Poly1305/None/NoPadding";
    private static final int BUFFER_SIZE = 16384;
    private static final int ACTION_INDEX = 0;
    private static final int PASSWORD_INDEX = 1;
    private static final int SOURCE_PATH_INDEX = 2;
    private static final int DESTINATION_INDEX = 3;
    private static final int PARAMETER_NUMBER = 4;

    /**
     * ChaCha constructor.
     * 
     * @param args
     *             String array with four element inside
     *             args[0] is action, should be "e" or "d"
     *             args[1] is password
     *             args[2] is source file path
     *             args[3] is destination file path
     */
    public ChaCha() {
    }

    /**
     * Process file encryption/decryption.
     */
    public Boolean process(String[] args) {
        boolean result = false;
        if (args.length == PARAMETER_NUMBER) {
            String action = args[ACTION_INDEX];
            String password = args[PASSWORD_INDEX];
            String srcFile = args[SOURCE_PATH_INDEX];
            String destFile = args[DESTINATION_INDEX];
            if ("e".equals(action)) {
                result = processEnc(password, srcFile, destFile);
            } else if ("d".equals(action)) {
                result = processDec(password, srcFile, destFile);
            } else {
                System.out.println("First parameter should be 'e' or 'd'.");
            }
        } else {
            System.out.println("Input parameters should be: e/d password soure destnation");
        }
        if (result) {
            System.out.println("Process completion. Everything is ok.");
        } else {
            System.out.println("Process fail.");
        }
        return result;
    }

    private byte[] getRandomBytes(int length) {
        byte[] bt = new byte[length]; // 12 byte (96 bit) for nonce, 32 (256 bit) byte for salt
        new SecureRandom().nextBytes(bt);
        return bt;
    }

    private SecretKey getKey(String passwd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passwd.toCharArray(), salt, KEY_ITERATION, KEY_BIT_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "ChaCha20");
    }

    private byte[] encrypt(byte[] input, SecretKey key, byte[] nonce)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, InvalidKeySpecException, IllegalBlockSizeException,
            BadPaddingException {

        Cipher cipher = Cipher.getInstance(ALGORITHM_STRING);
        IvParameterSpec iv = new IvParameterSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] encByte = cipher.doFinal(input);
        // System.out.println("Enc byte = " + encByte.length);
        return encByte;
    }

    private byte[] decrypt(byte[] input, SecretKey key, byte[] nonce)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(ALGORITHM_STRING);
        IvParameterSpec iv = new IvParameterSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] decByte = cipher.doFinal(input);
        // System.out.println("Dec byte = " + decByte.length);
        return decByte;
    }

    public Boolean processEnc(String password, String srcFile, String destFile) {
        try (
                FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);) {

            byte[] nonce = getRandomBytes(NONCE_LENGTH_BYTE);
            byte[] salt = getRandomBytes(SALT_LENGTH_BYTE);
            SecretKey key = getKey(password, salt);

            // System.out.println("Enc nonce = " + convertBytesToHex(nonce));
            // System.out.println("Enc salt = " + convertBytesToHex(salt));
            // System.out.println("Enc key = " + convertBytesToHex(key.getEncoded()));

            fos.write(nonce);
            fos.write(salt);
            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                if (nread < BUFFER_SIZE) {
                    fos.write(encrypt(Arrays.copyOf(buffer, nread), key, nonce));
                } else {
                    fos.write(encrypt(buffer, key, nonce));
                }
            }
            fos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | InvalidKeySpecException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean processDec(String password, String srcFile, String destFile) {
        try (
                FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);) {

            byte[] nonce = new byte[NONCE_LENGTH_BYTE];
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            fis.read(nonce);
            fis.read(salt);
            SecretKey key = getKey(password, salt);

            // System.out.println("Dec nonce = " + convertBytesToHex(nonce));
            // System.out.println("Dec salt = " + convertBytesToHex(salt));
            // System.out.println("Dec key = " + convertBytesToHex(key.getEncoded()));

            byte[] buffer = new byte[BUFFER_SIZE + 16];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                if (nread < (BUFFER_SIZE + 16)) {
                    fos.write(decrypt(Arrays.copyOf(buffer, nread), key, nonce));
                } else {
                    fos.write(decrypt(buffer, key, nonce));
                }
            }
            fos.flush();
        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidAlgorithmParameterException | InvalidKeySpecException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

    public static void main(String[] args) {
        long start = System.currentTimeMillis();
        new ChaCha().process(args);
        long end = System.currentTimeMillis();
        System.out.println("Process with " + (end - start)/1000.0 + " s.");
    }
}
