package com.midcielab;

import static org.junit.Assert.assertTrue;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Test;

/**
 * Unit test for ChaCha
 */
public class ChaChaTest {
    private static final int BUFFER_SIZE = 8192;

    @Test
    public void testChaCha() throws IOException, NoSuchAlgorithmException {
        String plain = "plan.txt";
        String enc = "enc.txt";
        String dec = "dec.txt";

        Files.deleteIfExists(new File(plain).toPath());
        Files.deleteIfExists(new File(enc).toPath());
        Files.deleteIfExists(new File(dec).toPath());

        SecureRandom sr = SecureRandom.getInstanceStrong();
        byte[] data = new byte[BUFFER_SIZE];
        sr.nextBytes(data);
        Files.write(Paths.get(plain), data, StandardOpenOption.CREATE);

        String[] encPara = { "e", "password5566", plain, enc };
        assertTrue(new ChaCha().process(encPara));

        String[] decPara = { "d", "password5566", enc, dec };
        assertTrue(new ChaCha().process(decPara));

        assertTrue(Arrays.equals(sha256(plain), sha256(dec)));

        Files.deleteIfExists(new File(plain).toPath());
        Files.deleteIfExists(new File(enc).toPath());
        Files.deleteIfExists(new File(dec).toPath());
    }

    public byte[] sha256(String digestFile) throws IOException, NoSuchAlgorithmException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int count;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(digestFile));
        while ((count = bis.read(buffer)) > 0) {
            md.update(buffer, 0, count);
        }
        bis.close();
        return md.digest();
    }
}
