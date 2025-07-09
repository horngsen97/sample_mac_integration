package util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class GenerateKeypair {
    /**
     * The constant that denotes the algorithm being used.
     */
    private static final String algorithm = "RSA";

    public static void main(String[] args) throws Exception {
        generateKey();
    }

    public static boolean generateKey() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(2048);

            final KeyPair key = keyGen.generateKeyPair();

            System.out.println("generated public key: " + StringFormatterUtil.convertBytesToBase64Url(key.getPublic().getEncoded()));
            System.out.println("generated private key: " + StringFormatterUtil.convertBytesToBase64Url(key.getPrivate().getEncoded()));

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

}
