package com.sunchp.digest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class B64Test {

    @Test
    public void testB64T() {
        assertNotNull(new B64()); // for the 100% code coverage :)
        assertEquals(64, B64.B64T.length());
    }

    @Test
    public void testB64from24bit() {
        final StringBuilder buffer = new StringBuilder("");
        B64.b64from24bit((byte) 8, (byte) 16, (byte) 64, 2, buffer);
        B64.b64from24bit((byte) 7, (byte) 77, (byte) 120, 4, buffer);
        assertEquals("./spo/", buffer.toString());
    }
}
