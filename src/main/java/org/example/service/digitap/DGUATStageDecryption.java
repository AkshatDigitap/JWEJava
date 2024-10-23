package org.example.service.digitap;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DGUATStageDecryption {
    public static void main(String[] args) throws Exception {
        String cipher2 = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.WbRgZBQBQZPHEaT-10XMVLjt1zfe90iCkwZOad16_9Z108okh6Hot8gR-U6ExPBJYvPv_g7msbz77HxHog17-yJay7R4YiZAsTN14avhKbFGyDmaeTDxmMbJ7aFPbb2OMwyrKPkX6E_weXOxw77xfPUSr3F2PaO92AT0DIpo0FCHgA6rMRxtLj6IX6P0qJTACZT20PWsJ8GCNWMyfFtOF6salz7a4VYOkvRqZExB-lgkKRwHWIJuFhKwNzJaIEqnv_YiCXUcsybEPrN5zkVjaCp3Um1_KU_WNy06ody-K3qaUXJx85SeuPhu1n_2Oekh74t7qfp7aqf828Yl2QYtOQ.xfPBpgOLxYtReu1q.6NTDN9Pu0r-7NBCZ68c._mxQ3rGGDhFVzfHCo9mWEw";
        String decryptedPayload = decryptencryptedTextPayloadToPlainText(cipher2);
        System.out.println("Plain Text is :- ");
        System.out.println(decryptedPayload);
    }

    public static String encryptReponseToEncryptedJWEObject(String inputPlainText) throws IOException, JOSEException {
        JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        RSAEncrypter rsaEncrypter = new RSAEncrypter((RSAPublicKey) getPublicKey());
        JWEObject jweObject = new JWEObject(jweHeader, new Payload(inputPlainText));
        jweObject.encrypt(rsaEncrypter);
        return jweObject.serialize();
    }

    public static String decryptencryptedTextPayloadToPlainText(String encryptedText) throws Exception {
        RSADecrypter rsaDecrypter = new RSADecrypter(getPrivateKey());
        JWEObject jweObject = JWEObject.parse(encryptedText);
        jweObject.decrypt(rsaDecrypter);
        Payload payload = jweObject.getPayload();
        JWEHeader jweHeader = jweObject.getHeader();
        return payload.toString();
    }

    public static PrivateKey getPrivateKey() throws Exception {
        //String privateKeyPEM = new String(Files.readAllBytes(Paths.get("DigitapPrivateKey.pem")));

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("DigitapUATStagePrivateKey.pem");
        if (inputStream == null) {
            throw new FileNotFoundException("Private key file not found: DigitapPrivateKey.pem");
        }

        String privateKeyPEM = new String(inputStream.readAllBytes());
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replaceAll("\\s+", "");

        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyDER);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }


    public static PublicKey getPublicKey() throws IOException {
        String publicKeyFilePath = "/home/akshatjaiswal/Workspace/Java_Workspace/Encryption/data/DigitapUATStagePublicKey.pem";
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(publicKeyFilePath)));
        PublicKey publicKey = null;
        try {
            String publicKeyPEMContent = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // Decode the Base64-encoded string
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEMContent);

            // Create a PublicKey object from the byte array
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return publicKey;
    }
}
