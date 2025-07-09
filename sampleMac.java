import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class sampleMac {
    public static PublicKey getPublicKey(String base64Url) throws Exception{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(convertBase64UrlToBytes(base64Url));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey getPrivateKey(String base64Url) throws Exception{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(convertBase64UrlToBytes(base64Url));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static String sign(String plainText, String privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey(privateKey));
        signature.update(plainText.getBytes());
        return convertBytesToBase64Url(signature.sign());
    }

    public static boolean verify(String plainText, String sign, String publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(getPublicKey(publicKey));
        signature.update(plainText.getBytes());
        byte[] signByte = isValidBase64Url(sign) ? convertBase64UrlToBytes(sign) : convertBase64ToBytes(sign);

        return signature.verify(signByte);
    }

    private static Boolean isValidBase64Url(String value) {
        if((value != null && value.replaceAll("[.A-Za-z0-9_-]", "").length() == 0) || value == null) {
            return true;
        }

        return false;
    }

    private static String convertBytesToBase64Url(byte[] value) {
        return new String(java.util.Base64.getUrlEncoder().withoutPadding().encode(value));
    }

    private static byte[] convertBase64UrlToBytes(String value) throws UnsupportedEncodingException {
        return java.util.Base64.getUrlDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] convertBase64ToBytes(String value) {
        value = removeBase64UselessChar(value);
        return java.util.Base64.getDecoder().decode(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String removeBase64UselessChar(String value) {
        return value.replaceAll(" ", "").replaceAll("\\r", "").replaceAll("\\n", "");
    }

    public static void main(String[] args) throws Exception {
        // For Request MAC  : this is provided by Client during the key exchange
        // For Response MAC : this is provided by Host during the key exchange
        String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiM9Mm3WrOrFcK0haJDU2hLkHfWrjFDeJiFphLpcaDjkqcWNdBSGiUAzFhTfyw01T2tmHMycLHchGyyZkm7Rppqh3iHftx4Kk3Ycmx6EIQMwOSSaGG5_CFzz69u94c5eH52DG8MAoLpWLs6x3YRUNGl2NLEMUNKVSt67raPZ20PI0EJjKmscfrXJfjrxgbu3pD6gb2NLtTExORvrWjxv0WBbLDmoVS5ReVWmYvsG9SHnJD_Wx1n9L567I66knHKsVm9E7se3-xNV87mV78gvTZfp3lksk_S9RNaUcHE6jGCuIfF8DDuF8PpX3sJNzUA-csPEzaRaTubF6BUXSuWDpAwIDAQAB";

        // For Request MAC  : this is provided by Client
        // For Response MAC : this is provided by Host
        String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCIz0ybdas6sVwrSFokNTaEuQd9auMUN4mIWmEulxoOOSpxY10FIaJQDMWFN_LDTVPa2YczJwsdyEbLJmSbtGmmqHeId-3HgqTdhybHoQhAzA5JJoYbn8IXPPr273hzl4fnYMbwwCgulYuzrHdhFQ0aXY0sQxQ0pVK3ruto9nbQ8jQQmMqaxx-tcl-OvGBu7ekPqBvY0u1MTE5G-taPG_RYFssOahVLlF5VaZi-wb1IeckP9bHWf0vnrsjrqSccqxWb0Tux7f7E1XzuZXvyC9Nl-neWSyT9L1E1pRwcTqMYK4h8XwMO4Xw-lfewk3NQD5yw8TNpFpO5sXoFRdK5YOkDAgMBAAECggEAKK43kdx984Bsr0Qe5bhbA0E_vGftqQPQphZ14lQ0_7i46amJre5v5My_aRsXWUKjpiZbwPahpBP7FQpQDUqqxc8_Z_l9X392BZdcDS1Rlm726oKFiy5ImP9dgtL3ZqvO0hrhXRJOgHegaGdmwhvv3wCla11w4yyruYnOX1I2R2_md4dYIwHVXAkUDsOTG5BjiOx_t7BLiYp1uUkIpmWjZvm2EFd66UoN-zlZv0kuGcHo4WUeR6irG9bxeoc0u7mrG4g3CMUErBwtOAGzx1vpelN6EJaI6J6dxSRX4Gy17O0AOnTrMpPWQG-w-Os9LKi9GhKg74UaiM4n-7JxonffIQKBgQDBReK705gxRDID4MQzOrGsTz1W4gV2KDgXn1tKXk9bwMazPrMOWokWw2wXakO4hlYO9aO0NAcZXGCMgcawa0rwcKFg2_BX19TfdKCC38Xl-C2cR_DrvtiP2nde7a4O4LlJPRx4EYW8p2j8znxXBP-QW6gD8ZlqCyekxAUZldYO4QKBgQC1Nih5vreX5s_k7TG8hCiYxQOyk6_EX5F2D-Kfw93Tzzo4Uuc95SY4H9_lRz0FIjHGV5bqlTjPSKFGZde6QxM-3i0A2NCD70iZes7p4ndqTyIkHW4qQKnrDGWW0CdxCO_gjWNZgQobRHffhKPeRRzpfaAcQKLsX9WZ7ourfAYoYwKBgQClb87O_CZQNZGiZClNuLYRSpq03i_Snka1YcDg_a1sWq07DTZz2Odzxr-lo15oewT7NSR1wfs5qCs02nla1dyFx8M7h8hJSQR8afZjUGyzlyZjmekNwoTZTiXT6huNvKqdmGPgGw-hFqP1kkI4spyX0v0Usx-g9_9tOCUta2aZwQKBgH5NBx0DzpazKwdWQyovutPvzUn0IbfvHEV7gOr163CrqNqE_eNoCaFopfb6Fg-z65lghzFtXDEtYCre5ONPyOQymo9SjtLGPoWq0Pi2_aA9E4C0eoo8k7Hd7BiXcEYagoayRSKnC9JBgINrwYM0DJi5FJVcf7HcgdZOK08UnH4dAoGBAKji9fgvTVdaivMdu29dDjrgGDywFMU9xlO4Ml-lsGp3KHaKu7W_CqZgMtfkvgLtNF3x4rgCKQAKVFg7P5hr-WjOtbqAK17ZAB-Npn52tq3yH0R5e5fXemcgi4I9oI-EvKGnneydqJ7c3NbaxeAcpUrzjyqe7T51wQA6m7UDxFNP";

        // Clear text of MAC
        String plainText = "0000000000000671000002020250514234352458100";

        // Mac for verify
        String sign = "DZ_YldUe7f7wMrhSFxYRIQlS_ovSpqcT82-T4s9scB__SFnuURZSbgZqoPAEk4pYMMmLMQKtX3hlcegaLveDQM8OdKruNIhwL6ndFSVn7c-Fh79S31fWJlDvNIw3eNW8p9qQ8T19fOpMFywIeYtRoT4S4HcTIRBItx1fdhRfzq1_ufKZ5kKsIzilB7KBoop50EIUoooyiOyIzRvpSLCsJVUcV32r42OKdWLVYGSYP7LIkhiCOx_s0YvpY15eY-akcvgf_Yvb-z08Agfz_Fd94J4PdDiV7mt7j8hHRlaevzRvmE5Ib9dN133Xb4R4v_cQ0Kgux-0bvo-kOjPQgJam5Q";

        // Simulate generate MAC
        String testSign = sign(plainText, privateKey);

        System.out.println("publicKey: " + publicKey);
        System.out.println("privateKey: " + privateKey);
        System.out.println("plainText: " + plainText);
        System.out.println("sign: " + testSign);

        // Simulate verify MAC
        System.out.println(verify(plainText, sign, publicKey));

    }
}
