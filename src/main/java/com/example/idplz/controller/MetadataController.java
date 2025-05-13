package com.example.idplz.controller;

import com.example.idplz.config.SamlIdpConfig;
import com.example.idplz.service.KeystoreService;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.*;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
// Import for X509Credential
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;
// This is the OpenSAML XMLObject for <ds:X509Certificate>
import org.opensaml.xmlsec.signature.X509Certificate; // as OpenSAMLX509CertificateElement;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;


import java.security.cert.CertificateEncodingException;
import java.util.Base64;


@RestController
public class MetadataController {

    private static final Logger LOG = LoggerFactory.getLogger(MetadataController.class);
    private final SamlIdpConfig samlIdpConfig;
    private final KeystoreService keystoreService;
    private final XMLObjectBuilderFactory builderFactory;

    public MetadataController(SamlIdpConfig samlIdpConfig, KeystoreService keystoreService) {
        this.samlIdpConfig = samlIdpConfig;
        this.keystoreService = keystoreService;
        this.builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    }

    @GetMapping(value = "/saml/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    public String getMetadata() throws CertificateEncodingException, MarshallingException {
        LOG.info("Generating IdP metadata for entity ID: {}", samlIdpConfig.getEntityId());

        EntityDescriptor entityDescriptor = create(EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
        entityDescriptor.setEntityID(samlIdpConfig.getEntityId());

        IDPSSODescriptor idpssoDescriptor = create(IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        idpssoDescriptor.setWantAuthnRequestsSigned(false); // You can set this to true if you want to enforce signed AuthnRequests
        idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

        // KeyDescriptor for signing
        Credential signingCredential = keystoreService.getSigningCredential();

        // Check if the credential is an X509Credential and get the certificate
        if (signingCredential instanceof X509Credential) {
            X509Credential x509SigningCredential = (X509Credential) signingCredential;
            java.security.cert.X509Certificate cert = x509SigningCredential.getEntityCertificate();

            if (cert != null) {
                KeyDescriptor signingKeyDescriptor = create(KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
                signingKeyDescriptor.setUse(UsageType.SIGNING);

                KeyInfo keyInfo = create(KeyInfo.class, KeyInfo.DEFAULT_ELEMENT_NAME);
                X509Data x509Data = create(X509Data.class, X509Data.DEFAULT_ELEMENT_NAME);
                org.opensaml.xmlsec.signature.X509Certificate opensamlX509CertificateElement = create(org.opensaml.xmlsec.signature.X509Certificate.class, org.opensaml.xmlsec.signature.X509Certificate.DEFAULT_ELEMENT_NAME);

                opensamlX509CertificateElement.setValue(Base64.getEncoder().encodeToString(cert.getEncoded()));
                x509Data.getX509Certificates().add(opensamlX509CertificateElement);
                keyInfo.getX509Datas().add(x509Data);
                signingKeyDescriptor.setKeyInfo(keyInfo);
                idpssoDescriptor.getKeyDescriptors().add(signingKeyDescriptor);
            } else {
                LOG.warn("X509SigningCredential was found, but it does not contain an entity certificate. Metadata will not include signing KeyDescriptor.");
            }
        } else if (signingCredential != null) {
            LOG.warn("Signing credential is not an X509Credential (type: {}). Metadata might not include the signing KeyDescriptor as expected.", signingCredential.getClass().getName());
        } else {
            LOG.warn("Signing credential not available. Metadata will not include signing KeyDescriptor.");
        }


        // SingleSignOnService Endpoint (HTTP-POST)
        SingleSignOnService ssoPostService = create(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoPostService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        ssoPostService.setLocation(samlIdpConfig.getSsoUrl());
        idpssoDescriptor.getSingleSignOnServices().add(ssoPostService);

        // SingleSignOnService Endpoint (HTTP-Redirect)
        SingleSignOnService ssoRedirectService = create(SingleSignOnService.class, SingleSignOnService.DEFAULT_ELEMENT_NAME);
        ssoRedirectService.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        ssoRedirectService.setLocation(samlIdpConfig.getSsoUrl()); // Same URL for both bindings in this example
        idpssoDescriptor.getSingleSignOnServices().add(ssoRedirectService);


        // NameID Formats supported
        NameIDFormat nameIDFormatUnspecified = create(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIDFormatUnspecified.setURI(NameIDType.UNSPECIFIED);
        idpssoDescriptor.getNameIDFormats().add(nameIDFormatUnspecified);

        NameIDFormat nameIDFormatEmail = create(NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
        nameIDFormatEmail.setURI(NameIDType.EMAIL);
        idpssoDescriptor.getNameIDFormats().add(nameIDFormatEmail);


        entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

        // Marshall to XML String
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(entityDescriptor);
        Element element = marshaller.marshall(entityDescriptor);
        String metadataXml = SerializeSupport.nodeToString(element);
        LOG.debug("Generated IdP Metadata XML: {}", metadataXml);
        return metadataXml;
    }

    @SuppressWarnings("unchecked")
    private <T extends XMLObject> T create(Class<T> cls, javax.xml.namespace.QName qname) {
        return (T) builderFactory.getBuilder(qname).buildObject(qname);
    }
}