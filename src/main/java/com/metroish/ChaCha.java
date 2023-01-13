package com.metroish;

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
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
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
    private static final int MSG_AUTH_CODE_LENGTH_BYTE = 16;
    private static final String ALGORITHM_STRING = "ChaCha20-Poly1305/None/NoPadding";
    private static final String KEY_DERIVATION_STRING = "PBKDF2WithHmacSHA256";
    private static final String KEY_SPEC_STRING = "ChaCha20";
    private static final int BUFFER_SIZE = 16384;
    private static final int ACTION_INDEX = 0;
    private static final int PASSWORD_INDEX = 1;
    private static final int SOURCE_PATH_INDEX = 2;
    private static final int DESTINATION_INDEX = 3;
    private static final int PARAMETER_NUMBER = 4;
    private static final Logger logger = Logger.getLogger(ChaCha.class.getName());

    /**
     * Process file encryption/decryption.
     * String array with four element inside
     * args[0] is action, should be "e", "ev", "d" or "dv"
     * args[2] is password
     * args[3] is source file path
     * args[4] is destination file path
     */
    public boolean process(String[] args) {
        boolean result = false;
        if (args.length == PARAMETER_NUMBER) {
            initialLogging(args[ACTION_INDEX].endsWith("v"));
            logger.info(() -> String.format("Source: %s", args[SOURCE_PATH_INDEX]));
            logger.info(() -> String.format("Destination: %s", args[DESTINATION_INDEX]));
            if (args[ACTION_INDEX].startsWith("e")) {
                logger.info("Encrypt start.");
                result = processEnc(args[PASSWORD_INDEX], args[SOURCE_PATH_INDEX], args[DESTINATION_INDEX]);
            } else if (args[ACTION_INDEX].startsWith("d")) {
                logger.info("Decrypt start.");
                result = processDec(args[PASSWORD_INDEX], args[SOURCE_PATH_INDEX], args[DESTINATION_INDEX]);
            } else {
                logger.info("First parameter should be 'e', 'ev', 'd' or 'dv'.");
            }
        } else {
            logger.info("Encrypt:  e password soure destnation \n");
            logger.info("Encrypt with verbose: ev password soure destnation \n");
            logger.info("Decrypt:  d password soure destnation \n");
            logger.info("Decrypt with verbose: dv password soure destnation \n");
        }
        if (result) {
            logger.info("Process completion. Everything is ok.");
        } else {
            logger.info("Process fail.");
        }
        return result;
    }

    private void initialLogging(boolean verbose) {
        ConsoleHandler consoleHandler = new ConsoleHandler();
        if (verbose) {
            consoleHandler.setLevel(Level.FINE);
            logger.setLevel(Level.FINE);
        } else {
            consoleHandler.setLevel(Level.INFO);
            logger.setLevel(Level.INFO);
        }
        consoleHandler.setFormatter(new SimpleFormatter() {
            private static final String FORMAT = "[%1$tF %1$tT][%2$-7s][%3$s] %4$s %n";

            @Override
            public String format(LogRecord logRecord) {
                return String.format(FORMAT,
                        new Date(logRecord.getMillis()),
                        logRecord.getLevel().getLocalizedName(),
                        logRecord.getSourceClassName(),
                        logRecord.getMessage());
            }
        });
        logger.addHandler(consoleHandler);
        logger.setUseParentHandlers(false);
    }

    private byte[] getRandomBytes(int length) {
        byte[] bt = new byte[length]; // 12 byte (96 bit) for nonce, 32 (256 bit) byte for salt
        new SecureRandom().nextBytes(bt);
        return bt;
    }

    private SecretKey getKey(String passwd, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_STRING);
        KeySpec spec = new PBEKeySpec(passwd.toCharArray(), salt, KEY_ITERATION, KEY_BIT_LENGTH);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), KEY_SPEC_STRING);
    }

    private byte[] crypt(byte[] input, SecretKey key, byte[] nonce, int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(ALGORITHM_STRING);
        IvParameterSpec iv = new IvParameterSpec(nonce);
        cipher.init(mode, key, iv);
        byte[] cryptByte = cipher.doFinal(input);
        logger.fine(() -> String.format("Process %d bytes", cryptByte.length));
        return cryptByte;
    }

    public boolean processEnc(String password, String srcFile, String destFile) {
        try (
                FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);) {

            byte[] nonce = getRandomBytes(NONCE_LENGTH_BYTE);
            byte[] salt = getRandomBytes(SALT_LENGTH_BYTE);
            SecretKey key = getKey(password, salt);

            logger.fine(() -> String.format("Enc nonce = %s", convertBytesToHex(nonce)));
            logger.fine(() -> String.format("Enc salt = %s", convertBytesToHex(salt)));
            logger.fine(() -> String.format("Enc key = %s", convertBytesToHex(key.getEncoded())));
            
            fos.write(nonce);
            fos.write(salt);

            byte[] buffer = new byte[BUFFER_SIZE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                if (nread < BUFFER_SIZE) {
                    fos.write(crypt(Arrays.copyOf(buffer, nread), key, nonce, Cipher.ENCRYPT_MODE));
                } else {
                    fos.write(crypt(buffer, key, nonce, Cipher.ENCRYPT_MODE));
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

    public boolean processDec(String password, String srcFile, String destFile) {
        try (
                FileInputStream fis = new FileInputStream(srcFile);
                FileOutputStream fos = new FileOutputStream(destFile);) {

            byte[] nonce = new byte[NONCE_LENGTH_BYTE];
            byte[] salt = new byte[SALT_LENGTH_BYTE];
            fis.read(nonce);
            fis.read(salt);
            SecretKey key = getKey(password, salt);

            logger.fine(() -> String.format("Dec nonce = %s", convertBytesToHex(nonce)));
            logger.fine(() -> String.format("Dec salt = %s", convertBytesToHex(salt)));
            logger.fine(() -> String.format("Dec key = %s", convertBytesToHex(key.getEncoded())));

            byte[] buffer = new byte[BUFFER_SIZE + MSG_AUTH_CODE_LENGTH_BYTE];
            int nread;
            while ((nread = fis.read(buffer)) > 0) {
                if (nread < (BUFFER_SIZE + MSG_AUTH_CODE_LENGTH_BYTE)) {
                    fos.write(crypt(Arrays.copyOf(buffer, nread), key, nonce, Cipher.DECRYPT_MODE));
                } else {
                    fos.write(crypt(buffer, key, nonce, Cipher.DECRYPT_MODE));
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
        logger.info(() -> String.format("Process with %s s.",
                String.valueOf((System.currentTimeMillis() - start) / 1000.0)));
    }
}
