package util;

import java.util.Base64;

public class StringFormatterUtil {
    public static String convertBytesToBase64Url(byte[] value) {
        return new String(Base64.getUrlEncoder().withoutPadding().encode(value));
    }
}
