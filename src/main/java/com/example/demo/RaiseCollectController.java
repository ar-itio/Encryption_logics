package com.example.demo;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/raiseCollect")
public class RaiseCollectController {

    @Autowired
    private RaiseCollectService raiseCollectService;

    @GetMapping("/encrypt")
    public String encryptData(@RequestParam Map<String, String> allParams) {
        try {
            return raiseCollectService.encryptDataToEncrypt(allParams);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while encrypting data";
        }
    }

    @GetMapping("/decrypt")
    public String decryptData(@RequestParam String encryptedData) {
        try {
            return raiseCollectService.decryptData(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while decrypting data: " + e.getMessage();
        }
    }

    @GetMapping("/sign")
    public String signData(@RequestParam Map<String, String> allParams) {
        try {
            return raiseCollectService.signData(allParams);
        } catch (Exception e) {
            e.printStackTrace();
            return "Error occurred while signing data";
        }
    }
}
