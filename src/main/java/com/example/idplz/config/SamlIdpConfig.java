package com.example.idplz.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Data
@Configuration
public class SamlIdpConfig {

   @Value("${idp.entityId}")
   private String entityId;

   @Value("${idp.ssoUrl}")
   private String ssoUrl;

   @Value("${idp.keystore.path}")
   private String keystorePath;

   @Value("${idp.keystore.password}")
   private String keystorePassword;

   @Value("${idp.keystore.alias}")
   private String keystoreAlias;

   @Value("${idp.keystore.keypassword}")
   private String keystoreKeyPassword;

   @Value("${idp.defaultAcsUrl}")
   private String defaultAcsUrl;

}
