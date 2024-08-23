
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
import java.util.Map;

@Service
public class QrService {

    public static final String CLIENT_PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCssBZioSFrRMVx"
        + "+S82i3vU4AnhVVq7UpSLdyxavt5NLmvtNK7wLQ7CCyIoTTLGkuSed39glelKe1JR"
        + "eQfxztFK/zL50DFEAYfcXXMKVqPuVKoES2cUca89mWqvkey6Bzckp/MkKyXaMmXg"
        + "cHniPB7zPeMYyytJvWhksha3k0dr7LdzUYkIknvnBlmS/aPYu6MJrDvl7pCV6sQ/"
        + "k92tR6fhv3PcQD3RpZqGaEq8jmPRDuJ0bCNhVHQCzdfXy7ABuAuJy5gtUodhgNBP"
        + "I2rtAJ+MA9Em8EX575oTKnnHZLV3+Hum7+evA+6KDBMClE/6osBVykoqpsxJmJ8G"
        + "CU0ciB7FAgMBAAECggEAEwuorGARC3+eNx/AcUeY9LVw4YVEaHyHHYqbPbbnVaPV"
        + "C2hQEvUlN4l6zu8Utonk5QVQ6xodjLVlMs8ibSzeMGNM//hSNqnkjg1Qbsd3dQWp"
        + "aqfWSo7vQN/2wD5b2XiKQGS1kDuiBRqh2csN5kGzOCiPL2DY+V0GcnShxMVdjy1x"
        + "+JqDQqqvToVvmZC1PtTNUFvTcQQFlwzAAAKaQAIV7zJ1/o6fOYR067awB3EqsVgF"
        + "yWejpDt6A2Jq0O1vZAQsMczRIymotA52WfutOIrHDY83LIAxbHGckH2AxEFmj7VL"
        + "Oj97Ej2PW8WUVDo9GjfXHf6GJFzfTNdS4DV9Dcj+UQKBgQDYMRQ81blUgTvWvNI3"
        + "Sf0nWtv/pyUm8ewJr4UGBeU1NUOOaT5ZQpAjVUnGm6dASae0JCpRTWiO2+NIth2f"
        + "V0GU54+hgKDhfAxpx7QgcsidjabiX4w7KRCD2BE+xiMN3RnbJm5XZKD5UND3XCgw"
        + "tLwuKVCXWtidcpO0RbqrExmBlwKBgQDMfE66YIoIC6ltMj67xKX4B3WSoorX5Mwv"
        + "jmhMcLAD12V4U4jXqXIshmtPon1gW9BU8G/TpAhKoQWKVoOxsdhZzfmOsEdB9RFt"
        + "vQ5qfMTX58HG1m4spxzR3vBieAq6aHCWCNbx11O+EPaJGRXMGIhP8sHN6Q7MCMto"
        + "kmSMGoB2AwKBgDATifqVVKd0LchtKRpee8t6qx3JH7vvZJwqyhwyx2vzslhDEzhq"
        + "Uv9oggWGq8TiHEc1G6wE2NGcGIkc5q1+i/j/HbO+lQhPu7ryTB5DKFXRIGGK+fZW"
        + "BXQsYnlhOn5kwtE3VKZenGWVEUNQ3Scnqglh6qgd7bnltu8J6p8Mmkl1AoGAekNl"
        + "CzkHrvHSFrExIzHcDmXfXZKEM7vgfhrGr9W82D8ks4I20sPEuWyRoybDkiazdOXh"
        + "5wgv0PdgCavayBdPBbsLGM67fGtcRWIByZfaVkGC8jFp5Jbyu2VyE141A+nIT1zv"
        + "r+AQeRdJYQW3q7WLY0oBqO1NZJ9ph5foOIDsCCMCgYEAlgR6ZJMvkePAFf4MXFR2"
        + "ppLwAPOxSuCpSTc54m8JwOV2iD0t509IrAebAm2oLaPPBF5scHAm7YnQQw9d9+3m"
        + "5g6z6JnHMSUI5lsDZy7hqpYaHzFyqAJlUmMBsMAOqwrMD33GvIr/FTsGkJ0UBwUW"
        + "BLEsrp3v11qdy5YJf3Z/3dQ=";
	
    private static final String SHARED_SYMMETRIC_KEY = "0d113e69b524db3a4fd7584affa7465c262cc03d89fe09ac75d1445141481f2b";
	
   

    public String encryptDataToEncrypt(Map<String, String> allParams) throws NoSuchAlgorithmException, UnsupportedEncodingException, JoseException, InvalidKeySpecException, DecoderException {
    	
    		var GET_DATA_TO_ENCRYPT = "{\n"
			    + "    \"amount\": \""+allParams.get("amount")+"\",\n"
			    + "    \"extTransactionId\": \""+allParams.get("transID")+"\",\n"
			    + "    \"channel\": \"api\",\n"
			    + "    \"remark\": \""+allParams.get("dba")+"\",\n"
			    + "    \"source\": \""+allParams.get("mid")+"\",\n"
			    + "    \"terminalId\": \"\",\n"
			    + "    \"type\": \"D\",\n"
			    + "    \"param3\": \"param3\",\n"
			    + "    \"Param2\": \"Param2\",\n"
			    + "    \"param1\": \"param1\",\n"
			    + "    \"sid\": \""+allParams.get("sid")+"\",\n"
			    + "    \"upiId\": \""+allParams.get("upiId")+"\",\n"
			    + "    \"requestTime\": \""+allParams.get("requestTime")+"\",\n"
			    + "    \"reciept\": \"https://google.com\",\n"
			    +"     \"checksum\": \"e1bd4415b9f44f724eb8f03602bc8524e2b513518a41dcdbc\"\n"
			    + "}";
	    	return encrypt(GET_DATA_TO_ENCRYPT);
    }

    public String decryptData(String encryptedInput) throws JoseException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, DecoderException {
        return decrypt(encryptedInput);
    }

    public String signData(Map<String, String> allParams) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
    		var GET_PAY_LOAD_PLAIN ="{\n"
				    + "    \"Request\": {\n"
				    + "        \"body\": {\n"
				    + "            \"encryptData\": {\n"
				    + "                \"amount\": \""+allParams.get("amount")+"\",\n"
				    + "                \"extTransactionId\": \""+allParams.get("transID")+"\",\n"
				    + "                \"channel\": \"api\",\n"
				    + "                \"remark\": \""+allParams.get("dba")+"\",\n"
				    + "                \"source\": \""+allParams.get("mid")+"\",\n"
				    + "                \"terminalId\": \"\",\n"
				    + "                \"type\": \"D\",\n"
				    + "                \"param3\": \"param3\",\n"
				    + "                \"Param2\": \"Param2\",\n"
				    + "                \"param1\": \"param1\",\n"
				    + "                \"sid\": \""+allParams.get("sid")+"\",\n"
				    + "                \"upiId\": \""+allParams.get("upiId")+"\",\n"
				    + "                \"requestTime\": \""+allParams.get("requestTime")+"\",\n"
				    + "                \"reciept\": \"https://google.com\",\n"
				    + "                \"checksum\": \"e1bd4415b9f44f724eb8f03602bc8524e2b513518a41dcdbc\"\n"
				    + "            }\n"
				    + "        }\n"
				    + "    }\n"
				    + "}";
        com.google.gson.JsonObject json = JsonParser.parseString(GET_PAY_LOAD_PLAIN).getAsJsonObject();
        return sign(json.toString());
    }
    

    public void demonstrateEncryptionAndDecryption() {
        try {
            // Encrypt the data
            String encryptedData = encryptDataToEncrypt(null);
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
