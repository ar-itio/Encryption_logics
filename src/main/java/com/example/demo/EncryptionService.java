package com.example.demo;

import org.apache.commons.codec.DecoderException;
import org.jose4j.jwe.*;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

import com.google.gson.JsonParser;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
public class EncryptionService {

    private static final String CLIENT_PRIVATE_KEY ="MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOYTIUTU4bxS7N"
	        + "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC51ZNctdJWFf5M
+"sqxNvQOUc5LWkQ4hIx5K6+xUhRUNWAlC1laQ3fdxfFI6q9642yLD9eYaTBmpreyb
+"9yjQ1fIPYKtnLeNNWbTVTm3qamb/EFlXuV738bux1I5H+rlDnA990E1zeCLb3i3d
+"hrysJlE+O+muT/wA8dwDhmhZ8YHRSPzudHu/nWKrwxkZDkhV10lLyW8uApvn5WhI
+"bDU7vy6e3p7kvg6yodTFSeBPjEQY240/Gl/bnZzsCFp/qRQSso4U/ir5QIZfKjjz
+"tRbaruLPAg4vxUft7bBGfY/iCVx1kySLwI9vsu3fCKMsVhzibBwBY631vUgcucsa
+"1CkKN6inAgMBAAECggEADDYbHVv7StneIIcbKG6TtiUUEJJulcHbgzvWh0VJeVuA
+"HEq+XH2hfW0YcC+MDqSjt7HIYZD/nLVHl4YZwgNVCSqmiLyss5ACAIRLV7yPMRKP
+"dGLDeVKCrXBUuykgFG/EWtWdyUkrLTx/0g9BBaTs8MR6GhC6dAtwlDC4WbSzfZ+L
+"/bKxAItmE1bQgo9SOQf7Fvf8VUPVweImwWkCGxeTf5dm8c84hqMxiuZ85MEOQovz
+pnS5uvQSMgywQsd610LSeiU5KJ4Lgwy0zEMqXNBX0HaAaY0Igi30tgL8m6lZ5tvk
+"VvB/6ip0L8pALYwQkhPtrHQFlVttxRHj3rq/RQMEMQKBgQDmj2iMR6BQ6O1tn1pf
+"/kTB5i7f+c567Lyx6Yvk7PpfNIgySJ72e+C1QUZM5V6eQjyVZVDMPKqRuo5Mx5cn
+"b5UcpggNoroqcIAQcJOIs7R8/yNY9pYWSqcvQv86a1nRxERYSdD1Llmp6zhvd85y
+"FzMFKh+90lVxAwspE5/36lSGUQKBgQDOVs15/caFfISJTU6vhXtHWQ5t9ZF8ZQGe
+"eFUugdnZLyLiHr34oJVNKfP0PH9xfa26gkquH2wBaEq/InZZfxTmCWrYt9qdYCl4
+"BZXaH82CU9GyZYiYfqjNhXVSIDmwMJ8gQ25/I3SmDUoJVTmjeT+VYGxUKWiqOCr+
+"2C0HYPZpdwKBgHbRRQG2D+pif6lUzBBYSzrZ0yJd7Ijw47WUNCH/9m+F9QJk5ncE
+"FCOUxhPuyLoqTGp5UhBO22BKkfcDjOQn3uJqtg/A4svoOjc+rOlwIv2fxqmcOnC2
+"fD4g+sMye5Fc4hPVxrfz8QVeUTEwvtWRGxv4P29lq96XwPKkSHZM7s5hAoGACqhP
+"GqLx8wkYa2MT0lsJoAjIhwNtDUjGSaIbfDh2wRH/MkC2PTZGH+Mv14icaIc+Rujd
+"5Jp44KW7Xp3wEPVQZgVMgH8WipRh7/IR6F9GJRohNZ6q7H12SI9BHQnPEPuh7G+v
+"MF/rcXw0O8EsJfZoQ1XkooA1CL238svFn6DxeUcCgYB6X2m1LFp0uKhvKEZElmx2
+"RPALFcnhpJZf0Z1uQiS3IiGWwLqlKtPhm0SJlewNoU79xmBnKLfMeDp5UaVTknyl
+"y61f0VpK+uM8GMWdyBrZTUeFkIgYuUPccud8OQWaMsLW3MnaP1yXMsL3mFzEGyyz
+"yDzwCa9hU5+WLF6s5KHYnQ==".replaceAll("\n", ""); // Replace with your actual private key
    private static final String SHARED_SYMMETRIC_KEY = "a3730a502c3b5574f616ac3a61f221b1695006a4765b086902373df280de17c2";
	
   private static final String DATA_TO_ENCRYPT = "{\n"
        + "    \"mid\": \"SKYWALK001\",\n"
        + "    \"channel\": \"api\",\n"
        + "    \"account_number\": \"120029938874\",\n"
        + "    \"mobile_number\": \"9256529287\",\n"
        + "    \"terminalId\": \"\",\n"
        + "    \"name\": \"SK PRIVATE LIMITED\",\n"
        + "    \"bank_name\": \"Canara Bank\",\n"
        + "    \"mcc\": \"6012\",\n"
        + "    \"ifsc_code\": \"CNRB0003896\",\n"
        + "    \"sid\": \"LETSPE0012",\n"
        + "    \"additionalNo\": \"\",\n"
        + "    \"checksum\": \"ytydtdgdggdg1200345\"\n"
        + "}";

    public String encryptDataToEncrypt() throws NoSuchAlgorithmException, UnsupportedEncodingException, JoseException, InvalidKeySpecException, DecoderException {
        return encrypt(DATA_TO_ENCRYPT);
    }

    public String decryptData(String encryptedInput) throws JoseException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, DecoderException {
        return decrypt(encryptedInput);
    }

    public String signData() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        com.google.gson.JsonObject json = JsonParser.parseString(PAY_LOAD_PLAIN).getAsJsonObject();
        return sign(json.toString());
    }
    private static final String PAY_LOAD_PLAIN ="{\n"
            + "    \"Request\": {\n"
            + "        \"body\": {\n"
            + "            \"encryptData\": {\n"
            + "                \"mid\": \"SKYWALK001\",\n"
            + "                \"channel\": \"api\",\n"
            + "                \"account_number\": \"120029938874\",\n"
            + "                \"mobile_number\": \"9256529287\",\n"
            + "                \"terminalId\": \"\",\n"
            + "                \"name\": \"Shankar Hotel\",\n"
            + "                \"bank_name\": \"Canara Bank\",\n"
            + "                \"mcc\": \"6012\",\n"
            + "                \"ifsc_code\": \"CNRB0003896\",\n"
            + "                \"sid\": \"LETSPE0012\",\n"
            + "                \"additionalNo\": \"\",\n"
            + "                \"checksum\": \"ytydtdgdggdg1200345\"\n"
            + "            }\n"
            + "        }\n"
            + "    }\n"
            + "}";

    public void demonstrateEncryptionAndDecryption() {
        try {
            // Encrypt the data
            String encryptedData = encryptDataToEncrypt();
            System.out.println("Encrypted Data: " + encryptedData);

            // Decrypt the data
            String decryptedData = decryptData(encryptedData);
            System.out.println("Decrypted Data: " + decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encrypt(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException, JoseException, InvalidKeySpecException, DecoderException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A256KW);
        jwe.setKey(new AesKey(digest()));
        jwe.setPayload(input);
        return "Encrypted Data:  "+jwe.getCompactSerialization() ;
    }

    private String decrypt(String input) throws JoseException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, DecoderException {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(input);
        AesKey aes = new AesKey(digest());
        jwe.setKey(aes);
        return "     Decrypted Data:  "+jwe.getPlaintextString();
    }

    private String sign(String input) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        String realPK = CLIENT_PRIVATE_KEY.replaceAll("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("-----BEGIN RSA PRIVATE KEY-----", "")
                .replaceAll("\n", "");
        byte[] b1 = Base64.getDecoder().decode(realPK);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(input.getBytes("UTF-8"));
        byte[] s = privateSignature.sign();
        return Base64.getEncoder().encodeToString(s);
    }

    private byte[] digest() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, DecoderException {
        byte[] val = new byte[SHARED_SYMMETRIC_KEY.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(SHARED_SYMMETRIC_KEY.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }
}
