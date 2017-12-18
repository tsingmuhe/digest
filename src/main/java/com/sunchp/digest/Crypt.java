package com.sunchp.digest;

import java.nio.charset.StandardCharsets;

public class Crypt {

    public static String crypt(final byte[] keyBytes) {
        return crypt(keyBytes, null);
    }

    public static String crypt(final byte[] keyBytes, final String salt) {
        if (salt == null) {
            return Sha2Crypt.sha512Crypt(keyBytes);
        }

        if (salt.startsWith(Sha2Crypt.SHA512_PREFIX)) {
            return Sha2Crypt.sha512Crypt(keyBytes, salt);
        }

        if (salt.startsWith(Sha2Crypt.SHA256_PREFIX)) {
            return Sha2Crypt.sha256Crypt(keyBytes, salt);
        }

        if (salt.startsWith(Md5Crypt.MD5_PREFIX)) {
            return Md5Crypt.md5Crypt(keyBytes, salt);
        }

        throw new IllegalArgumentException("Invalid salt value: " + salt);
    }

    public static String crypt(final String key) {
        return crypt(key, null);
    }

    public static String crypt(final String key, final String salt) {
        return crypt(key.getBytes(StandardCharsets.UTF_8), salt);
    }
}
