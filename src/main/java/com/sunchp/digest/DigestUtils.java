package com.sunchp.digest;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class DigestUtils {
    public static MessageDigest getDigest(final String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static MessageDigest getMd5Digest() {
        return getDigest(MessageDigestAlgorithms.MD5);
    }

    public static MessageDigest getSha1Digest() {
        return getDigest(MessageDigestAlgorithms.SHA_1);
    }

    public static MessageDigest getSha256Digest() {
        return getDigest(MessageDigestAlgorithms.SHA_256);
    }

    public static MessageDigest getSha384Digest() {
        return getDigest(MessageDigestAlgorithms.SHA_384);
    }

    public static MessageDigest getSha512Digest() {
        return getDigest(MessageDigestAlgorithms.SHA_512);
    }

    public static byte[] md5(final byte[] data) {
        return getMd5Digest().digest(data);
    }

    public static byte[] md5(final String data) {
        return md5(getBytesUtf8(data));
    }

    public static String md5Hex(final byte[] data) {
        return Hex.encodeHexString(md5(data));
    }

    public static String md5Hex(final String data) {
        return Hex.encodeHexString(md5(data));
    }

    public static byte[] sha1(final byte[] data) {
        return getSha1Digest().digest(data);
    }

    public static byte[] sha1(final String data) {
        return sha1(getBytesUtf8(data));
    }

    public static String sha1Hex(final byte[] data) {
        return Hex.encodeHexString(sha1(data));
    }

    public static String sha1Hex(final String data) {
        return Hex.encodeHexString(sha1(data));
    }

    public static byte[] sha256(final byte[] data) {
        return getSha256Digest().digest(data);
    }

    public static byte[] sha256(final String data) {
        return sha256(getBytesUtf8(data));
    }

    public static String sha256Hex(final byte[] data) {
        return Hex.encodeHexString(sha256(data));
    }

    public static String sha256Hex(final String data) {
        return Hex.encodeHexString(sha256(data));
    }

    public static byte[] sha384(final byte[] data) {
        return getSha384Digest().digest(data);
    }

    public static byte[] sha384(final String data) {
        return sha384(getBytesUtf8(data));
    }

    public static String sha384Hex(final byte[] data) {
        return Hex.encodeHexString(sha384(data));
    }

    public static String sha384Hex(final String data) {
        return Hex.encodeHexString(sha384(data));
    }

    public static byte[] sha512(final byte[] data) {
        return getSha512Digest().digest(data);
    }

    public static byte[] sha512(final String data) {
        return sha512(getBytesUtf8(data));
    }

    public static String sha512Hex(final byte[] data) {
        return Hex.encodeHexString(sha512(data));
    }

    public static String sha512Hex(final String data) {
        return Hex.encodeHexString(sha512(data));
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
}
