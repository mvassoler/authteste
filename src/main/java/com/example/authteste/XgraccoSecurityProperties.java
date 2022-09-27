package com.example.authteste;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Component
@Getter
@Setter
@Validated
@ConfigurationProperties("xgracco.auth")
public class XgraccoSecurityProperties {

    @NotBlank
    private String providerUrl;
}
