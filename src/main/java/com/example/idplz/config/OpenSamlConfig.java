package com.example.idplz.config;

import jakarta.annotation.PostConstruct;
import org.opensaml.core.config.InitializationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenSamlConfig {

   private static final Logger LOG = LoggerFactory.getLogger(OpenSamlConfig.class);

   @PostConstruct
   public void initializeOpenSaml() {
       try {
           LOG.info("Initializing OpenSAML...");
           InitializationService.initialize();
           LOG.info("OpenSAML initialized successfully.");
       } catch (Exception e) {
           LOG.error("Error initializing OpenSAML: {}", e.getMessage(), e);
           // Throwing a runtime exception to prevent application startup in case of OpenSAML init failure
           throw new RuntimeException("Failed to initialize OpenSAML", e);
       }
   }
}