package com.example.idplz.service;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.Collections;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.impl.KeyStoreCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import com.example.idplz.config.SamlIdpConfig;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;

@Service
public class KeystoreService {

   private static final Logger LOG = LoggerFactory.getLogger(KeystoreService.class);
   private final SamlIdpConfig samlIdpConfig;
   private Credential signingCredential;

   public KeystoreService(SamlIdpConfig samlIdpConfig) {
       this.samlIdpConfig = samlIdpConfig;
       loadSigningCredential();
   }

   private void loadSigningCredential() {
       try {
           KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
           // Make sure keystore path starts with classpath: or file:
           InputStream keystoreStream = new ClassPathResource(samlIdpConfig.getKeystorePath().replace("classpath:", "")).getInputStream();

           char[] password = samlIdpConfig.getKeystorePassword().toCharArray();
           ks.load(keystoreStream, password);
           keystoreStream.close();

           KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(ks, Collections.singletonMap(samlIdpConfig.getKeystoreAlias(), samlIdpConfig.getKeystoreKeyPassword()));
           this.signingCredential = resolver.resolveSingle(new CriteriaSet(new org.opensaml.core.criterion.EntityIdCriterion(samlIdpConfig.getKeystoreAlias())));

           if (this.signingCredential == null) {
               LOG.error("Failed to load signing credential for alias: {}", samlIdpConfig.getKeystoreAlias());
               throw new RuntimeException("Signing credential could not be loaded from keystore.");
           }
           LOG.info("Successfully loaded signing credential for alias: {}", samlIdpConfig.getKeystoreAlias());

       } catch (Exception e) {
           LOG.error("Error loading signing credential from keystore: {}", e.getMessage(), e);
           throw new RuntimeException("Error loading signing credential", e);
       }
   }

   public Credential getSigningCredential() {
       if (signingCredential == null) {
           LOG.warn("Signing credential not loaded, attempting to reload.");
           loadSigningCredential(); // Attempt to reload if not initialized
       }
       return signingCredential;
   }
}