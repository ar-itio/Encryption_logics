package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/encryption")
public class EncryptionController {

    @Autowired
    private EncryptionService encryptionService;

    @GetMapping("/encrypt")
    public String encryptData() {
        try {
            return encryptionService.encryptDataToEncrypt();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while encrypting data";
        }
    }

    @GetMapping("/decrypt")
    public String decryptData(@RequestParam String encryptedData) {
        try {
            return encryptionService.decryptData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while decrypting data: " + e.getMessage();
        }
    }

    @GetMapping("/sign")
    public String signData() {
        try {
            return encryptionService.signData();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while signing data";
        }
    }
}
