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

  public static final String CLIENT_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwZ+K+Ux2kRpHjDP2SgvCkSEaMuS8mot8H5qJzBSghyyXy2IosuyrbQpGrmSEKCgamJuGJqRBUgZXsdal0QpinTizaYdDRaPP+DCnylK9yAEyTEGU6dmTHRUMe1ae/Y3EnTWSsYHAAlPHPVJ5+pJLkuqNHIXZnZHqyPKAXzejcY3vlOD6w6qpPKCv3dGvv7sqpwnhB67TGYn0zEhm7tnjcQ6oZGrjNVIZZ9IAmtfiNJPe5h+XysuKQ6sy5egAXYuF0JDIHW2Y5JaHqjtrWzA3xxunj9fAq10FhQ37kVVHC3N+Y9sXYxYHp4zHog58zx+21ZYPyKuW8JX8uyhBpj4LtAgMBAAECggEAL7lLLHZL9J9q5GQlTbfC5o7vFy8aRHeXowmQNVHV056j+5j9eLCCHaNayXO57n9b4SNvrNBiLJqKNth2KY/CwLBzjfkchyq/p6Ee0BPNiyftj3PGDxTsmsRwLi1bHnoGqL1VWRUV9/JToOWho11eqCad+aZh5ALY9tNT9FyufMCyTinpg117Bdr723HsAl9WjUZgtT/3+p8OcqKKSJ7kvoEyW8VIdVnYq7L5hN2AP8ceiEnp3uDvaUd18gGIUVz4V+TbIcyeC++Wle0be1NY3cSfSXvBcRzaXAYTFPQP2/2uFEQjPltGEuS1PtOSToq6w7O0roWXiGEhjWkCGxW7QQKBgQDVFeOupYExcLUEXltt72lTZ0go40hSdLzMUb8WeJEo7hWFHrVW9QB9sNWdcNTlPeBKWmRjWsWB8Ueh5Ac+FmI+Y8MKk7+MSsEXhrL02deLhAs8sFDYM5OKFKhh8F8ssHYSVo01mYGvd9piuwUkag54Tr/YKA18121Dh+jBF74VKQKBgQDT7uPx1agLWIPvzODcrEt3XchWa9NU/3JUw9rW+eUnxTQq2uyzCiqm4zo+dPn7EBfazf5QP5Q6YvPy/f/+WF4W0mQOUZDSgG6cgNtFibFO+0UIOPF9i3XMIt8amVseOiTQwR/JywZsCwRGBAr7UhHOIrhg0ehrJXQj/kjX0p1UJQKBgElTNv4qRcLVnfTa42t5Ly1cJSCs1X5KXY2Rs8fvxUPoac9dOdmqhXi7GUcMRLZ+DGiJonHuEnkcpiG3biaXXUdK3RsOrKOCNd/6oipPrDR+Q7+mjKtZVDP319mb9aRTNM4qqnz/TfkrrSK8aJCXTlNoBexEHCARoa/TXOzVVrvBAoGBAMnzUD64K8Nz+3Vcs8FUZS0/rpG7ecv7BwWDBFvqENVO86EKsJcDTxVsXan6aeM1uKWFuZramvLwLCoWpAPITRBON431Z51PSRfVKh0fUlhC08s8B9JsPDnj2NlN3Sf2m/JYtWPjFSGLde0KGTTXRaQ6LZwFKgY/0GYj/2G5jrYJAoGAfVCuCPgyIjXEGWhTwBbW0szjQZrGAyBJnonKKLgH4ehEIlZJcfxiEORVTCSY7zkfK4wARJujSW/b6HXN8MpaKIbuZTwaIYXGZCQxWyGq7J7m7VJZR6DKnWlLHpzlL1pBghC4qsDyR6Og7zZPlVl/ZaM1u0G/RtPwh6LJ0YJ47Ko=";
	
    private static final String SHARED_SYMMETRIC_KEY = "0d113e69b524db3a4fd7584affa7465c262cc03d89fe09ac75d1445141481f2b";
	
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
        + "    \"sid\": \"LETSPE0012\",\n"
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
            + "                \"name\": \"SK PRIVATE LIMITED\",\n"
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
