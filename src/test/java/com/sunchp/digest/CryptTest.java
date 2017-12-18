package com.sunchp.digest;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CryptTest {
    @Test
    public void testDefaultCryptVariant() {
        // If salt is null or completely omitted, a random "$6$" is used.
        assertTrue(Crypt.crypt("secret").startsWith("$6$"));
        assertTrue(Crypt.crypt("secret", null).startsWith("$6$"));
    }

    @Test
    public void testCryptWithBytes() {
        final byte[] keyBytes = new byte[]{'b', 'y', 't', 'e'};
        final String hash = Crypt.crypt(keyBytes);
        assertEquals(hash, Crypt.crypt("byte", hash));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCryptWithEmptySalt() {
        Crypt.crypt("secret", "");
    }
}
