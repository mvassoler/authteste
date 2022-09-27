package com.example.authteste;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.TimeZone;

@SpringBootApplication
public class AuthtesteApplication {

    public static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        var app = new SpringApplication(AuthtesteApplication.class);
        app.addListeners(new Base64ProtocolResolver());
        app.run(args);
    }

}
