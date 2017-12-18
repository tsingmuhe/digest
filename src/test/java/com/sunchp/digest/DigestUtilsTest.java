package com.sunchp.digest;

import org.junit.Test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class DigestUtilsTest {
    @Test(expected = IllegalArgumentException.class)
    public void testInternalNoSuchAlgorithmException() {
        DigestUtils.getDigest("Bogus Bogus");
    }

    private static byte[] getBytesUtf8(final String string) {
        return getBytes(string, StandardCharsets.UTF_8);
    }

    private static byte[] getBytes(final String string, final Charset charset) {
        if (string == null) {
            return null;
        }

        return string.getBytes(charset);
    }

    @Test
    public void testMd5Hex() throws IOException {
        // Examples from RFC 1321
        assertEquals("d41d8cd98f00b204e9800998ecf8427e", DigestUtils.md5Hex(""));

        assertEquals("0cc175b9c0f1b6a831c399e269772661", DigestUtils.md5Hex("a"));

        assertEquals("900150983cd24fb0d6963f7d28e17f72", DigestUtils.md5Hex("abc"));

        assertEquals("f96b697d7cb7938d525a2f31aaf161d0", DigestUtils.md5Hex("message digest"));

        assertEquals("c3fcd3d76192e4007dfb496cca67e13b", DigestUtils.md5Hex("abcdefghijklmnopqrstuvwxyz"));

        assertEquals(
                "d174ab98d277d9f5a5611c2c9f419d9f",
                DigestUtils.md5Hex("ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" + "0123456789"));

        assertEquals(
                "57edf4a22be3c955ac49da2e2107b67a",
                DigestUtils.md5Hex("1234567890123456789012345678901234567890" + "1234567890123456789012345678901234567890"));
    }

    /**
     * An MD5 hash converted to hex should always be 32 characters.
     */
    @Test
    public void testMd5HexLengthForBytes() {
        String hashMe = "this is some string that is longer than 32 characters";
        String hash = DigestUtils.md5Hex(getBytesUtf8(hashMe));
        assertEquals(32, hash.length());

        hashMe = "length < 32";
        hash = DigestUtils.md5Hex(getBytesUtf8(hashMe));
        assertEquals(32, hash.length());
    }

    /**
     * An MD5 hash should always be a 16 element byte[].
     */
    @Test
    public void testMd5LengthForBytes() {
        String hashMe = "this is some string that is longer than 16 characters";
        byte[] hash = DigestUtils.md5(getBytesUtf8(hashMe));
        assertEquals(16, hash.length);

        hashMe = "length < 16";
        hash = DigestUtils.md5(getBytesUtf8(hashMe));
        assertEquals(16, hash.length);
    }

    @Test
    public void testSha1Hex() throws IOException {
        // Examples from FIPS 180-1
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", DigestUtils.sha1Hex("abc"));

        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", DigestUtils.sha1Hex(getBytesUtf8("abc")));

        assertEquals(
                "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
                DigestUtils.sha1Hex("abcdbcdecdefdefgefghfghighij" + "hijkijkljklmklmnlmnomnopnopq"));
    }


    @Test
    public void testSha256() throws IOException {
        // Examples from FIPS 180-2
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                DigestUtils.sha256Hex("abc"));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                DigestUtils.sha256Hex(getBytesUtf8("abc")));
        assertEquals("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                DigestUtils.sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"));
    }

    @Test
    public void testSha384() throws IOException {
        // Examples from FIPS 180-2
        assertEquals("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" +
                        "8086072ba1e7cc2358baeca134c825a7",
                DigestUtils.sha384Hex("abc"));
        assertEquals("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed" +
                        "8086072ba1e7cc2358baeca134c825a7",
                DigestUtils.sha384Hex(getBytesUtf8("abc")));
        assertEquals("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712" +
                        "fcc7c71a557e2db966c3e9fa91746039",
                DigestUtils.sha384Hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" +
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    }

    @Test
    public void testSha512() throws IOException {
        // Examples from FIPS 180-2
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                DigestUtils.sha512Hex("abc"));
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
                        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                DigestUtils.sha512Hex(getBytesUtf8("abc")));
        assertEquals("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018" +
                        "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
                DigestUtils.sha512Hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn" +
                        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
    }
}
