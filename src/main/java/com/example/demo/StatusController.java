package com.example.demo;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/Status")
public class StatusController {

    @Autowired
    private StatusService statusService;

    @GetMapping("/encrypt")
    public String encryptData(@RequestParam Map<String, String> allParams) {
        try {
            return statusService.encryptDataToEncrypt(allParams);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while encrypting data";
        }
    }

    @GetMapping("/decrypt")
    public String decryptData(@RequestParam String encryptedData) {
        try {
            return statusService.decryptData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while decrypting data: " + e.getMessage();
        }
    }

    @GetMapping("/sign")
    public String signData(@RequestParam Map<String, String> allParams) {
        try {
            return statusService.signData(allParams);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while signing data";
        }
    }
}
