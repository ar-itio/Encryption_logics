
package com.example.demo;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/api/QR")
public class QrController {

    @Autowired
    private QrService qRService;

    @GetMapping("/encrypt")
    public String encryptData(@RequestParam Map<String, String> allParams) {
        try {
            
            // Encrypt the JSON formatted data
            return qRService.encryptDataToEncrypt(allParams);
            
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while encrypting data";
        }
    }

    @GetMapping("/decrypt")
    public String decryptData(@RequestParam String encryptedData) {
        try {
            return qRService.decryptData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while decrypting data: " + e.getMessage();
        }
    }

    @GetMapping("/sign")
    public String signData(@RequestParam Map<String, String> allParams) {
        try {
            return qRService.signData(allParams);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while signing data";
        }
    }
    
    
    
    private String buildJsonInput(Map<String, String> params) {
        // Construct your JSON input here from the params
        // This is a simple example, you may need to adjust it according to your needs
        return String.format("{\"amount\":\"%s\",\"extTransactionId\":\"%s\",\"channel\":\"%s\",\"remark\":\"%s\",\"source\":\"%s\",\"terminalId\":\"%s\",\"type\":\"%s\",\"param3\":\"%s\",\"Param2\":\"%s\",\"param1\":\"%s\",\"sid\":\"%s\",\"upiId\":\"%s\",\"requestTime\":\"%s\",\"reciept\":\"%s\",\"checksum\":\"%s\"}",
                params.get("amount"), params.get("extTransactionId"), params.get("channel"), params.get("remark"), params.get("source"), params.get("terminalId"), params.get("type"), params.get("param3"), params.get("Param2"), params.get("param1"), params.get("sid"), params.get("upiId"), params.get("requestTime"), params.get("reciept"), params.get("checksum"));
    }
}
