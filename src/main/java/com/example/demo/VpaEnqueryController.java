package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/VpaEncryption")
public class VpaEnqueryController {

    @Autowired
    private VpaEnqueryService vpaEnqueryService;

    @GetMapping("/encrypt")
    public String encryptData() {
        try {
            return vpaEnqueryService.encryptDataToEncrypt();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while encrypting data";
        }
    }

    @GetMapping("/decrypt")
    public String decryptData(@RequestParam String encryptedData) {
        try {
            return vpaEnqueryService.decryptData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while decrypting data: " + e.getMessage();
        }
    }

    @GetMapping("/sign")
    public String signData() {
        try {
            return vpaEnqueryService.signData();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while signing data";
        }
    }
}

