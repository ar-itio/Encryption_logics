
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
public class QrService {

    private static final String CLIENT_PRIVATE_KEY ="MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCOYTIUTU4bxS7N"
	        + "x7k9QE3NY6Z7xQhAykXNYmGk6LfO5fmUXuQ9s9CpefywLTRAgCBy/IJFZLgjVHD9"
	        + "F1bhaJdaYdPC3FOkHUTIr7g/BN4fskvO7aJnuArkC8rXvXU+LiQPwqUFN4HclN4X"
	        + "GGMacUGzFiIy972cYLF8rjNktRDATnuzWHWjyi8CEJgoFZSeqOHz8U4Kq2EBT1oU"
	        + "3/q3Cfpx3UOpPv3mrEBgS7vft0Np06kSHcl7ekLd3veVby7Xz55O4jvfS0ZuCs+8"
	        + "JpbXhlORm0ysM8WNKQICUn/dplHhXfIrtizefhDEGw9HeqssKv0ceXGTvBR8vJ8s"
	        + "5YCJ/pmNAgMBAAECggEAFAqYawUqrnwGB49KgtWvXe7d+2QTslMGmk9z4Suk2+nB"
	        + "ROJKjGjoQULbj8z9IusmJilnCO+Rf9+d+/IyF46KZ32HulEbMOmxyfH6JFzCC4Ik"
	        + "a59FkgX0+n6yccXIYBVMnC9Q3Tgf/nWyAVw8bvdsQRInhDcdKIrv0NYQg+d80STF"
	        + "OsGArNcx+xdpPUMuVHlZ9eG24QQHiDc5I031J7ecMRJmJ0C+JKQowH08WaBifCuG"
	        + "G9M35hIuvb0d1Z5LF8MRXvGj0Vwn1Sk1slLlEFUedG3BKrj5sVnrzDYcfTPjRCDk"
	        + "FwrdyBXKqgUiCkAfPhu4nCx893x2NcYFc8cfUK7foQKBgQDFyxSH7J39PYIiMae9"
	        + "lK9gpWOqA7yn6lb2tp3VXQW8fzLj7XqGvl6rC9GCXkLpdEzTbospHqWbWVVVCY60"
	        + "JXccWotr8AlGfYI6f00wRRAl9M9Eb+xwE7YGAPhWIFVubz4KvgPsJG+U+4SNavyG"
	        + "lxZ8DoWkPJgCVVjJyMoP9HoVxQKBgQC4R3xAICEZXfOMHeD9JnSmirKxzIUWtrW/"
	        + "vE2CzBQP+U8t0dUFiRbK5gezuTaFEXish9AhLFkV97T3MX1HVCCyhI8f/syGmtaY"
	        + "FMngleXMG/HeGMD7OFtWMPmSPWcTdDq0ggLRZHUj5wIfa0P2u1lqt9basG5BxHrq"
	        + "dZoXXvt5KQKBgB+W/rFyzgzbHQSfD55Mt/HkmFVYAXKED92Zbv3bvIXNfvA+Rnps"
	        + "vyvsWErNCTzF8Vs3ZYxss6BrFSDexObqsOpbX7cegCy88Oas3EQgU6LsRYo1ofqI"
	        + "e2LcFs2SnnJj2/HVRUUa0KNnxFTdyHUqflHT8+42K0T8IpEfu33u2uzNAoGASdYC"
	        + "t+LnwDU/x22VX3lQFgbO0KTE0rQEoL1/RSAmDbxz+ETyGJS0ODnw7hcQ/EJi2qZU"
	        + "Q2Z0j3O/46fFrZXMwBqTClvacTiLMUZrGPyWpbCwua+raz1Kg39+EBVgPpA8kWTi"
	        + "YinhMbB2zkX5Zlvs2PCuOtOkad+i7FyQkDqzgfkCgYAGYK5gySyJQI1n5AhAeKeF"
	        + "tCTncH9//gFrhzSqkvpfgdJ+Z4dawFgCbgzemSzYorI3FYKlP9Ma7s5e9YzWPMh+"
	        + "oLaearrayzS6MbEifRecc1+twLxqrbqwXTmxmywSU0ouZpCczqHk0+6Sm4S9dTt7"
	        + "Ev6QpSq6BEuJ3uml7xgFlw==".replaceAll("\n", ""); // Replace with your actual private key
    private static final String SHARED_SYMMETRIC_KEY = "a3730a502c3b5574f616ac3a61f221b1695006a4765b086902373df280de17c2";
	
   private static final String DATA_TO_ENCRYPT = "{\n"
        + "    \"mid\": \"AGRLOG0000\",\n"
        + "    \"channel\": \"api\",\n"
        + "    \"account_number\": \"04762020001837\",\n"
        + "    \"mobile_number\": \"914567899787\",\n"
        + "    \"terminalId\": \"YOUTUBE456\",\n"
        + "    \"name\": \"Shankar Hotel\",\n"
        + "    \"bank_name\": \"Canara Bank\",\n"
        + "    \"mcc\": \"6012\",\n"
        + "    \"ifsc_code\": \"CNRB0000000\",\n"
        + "    \"sid\": \"YOUTUBE975\",\n"
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
            + "                \"mid\": \"AGRLOG0000\",\n"
            + "                \"channel\": \"api\",\n"
            + "                \"account_number\": \"04762020001837\",\n"
            + "                \"mobile_number\": \"914567899787\",\n"
            + "                \"terminalId\": \"YOUTUBE456\",\n"
            + "                \"name\": \"Shankar Hotel\",\n"
            + "                \"bank_name\": \"Canara Bank\",\n"
            + "                \"mcc\": \"6012\",\n"
            + "                \"ifsc_code\": \"CNRB0000000\",\n"
            + "                \"sid\": \"YOUTUBE975\",\n"
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

