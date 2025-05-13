package com.example.idplz.service;

import com.example.idplz.config.SamlIdpConfig;
import com.example.idplz.dto.SamlLoginRequest;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
// import org.opensaml.saml.saml2.core.impl.*; // Not strictly needed for this class's direct usage
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential; // Import for X509Credential
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory; // Import for KeyInfo generation
import org.opensaml.xmlsec.signature.KeyInfo; // Import for KeyInfo
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
// import org.opensaml.xmlsec.signature.support.SignerProvider; // Not directly used
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.time.Instant;
import java.util.UUID;
import java.util.Map;

@Service
public class SamlResponseGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(SamlResponseGenerator.class);
    private final SamlIdpConfig samlIdpConfig;
    private final KeystoreService keystoreService;
    private final XMLObjectBuilderFactory builderFactory;

    public SamlResponseGenerator(SamlIdpConfig samlIdpConfig, KeystoreService keystoreService) {
        this.samlIdpConfig = samlIdpConfig;
        this.keystoreService = keystoreService;
        this.builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    }

    public String generateSamlResponse(SamlLoginRequest loginRequest, String acsUrl, String recipient, String inResponseToId, String audienceSpEntityId) throws Exception {
        LOG.info("Generating SAML Response for user: {}, ACS: {}, InResponseTo: {}", loginRequest.getUsername(), acsUrl, inResponseToId);

        Response response = create(Response.class, Response.DEFAULT_ELEMENT_NAME);
        response.setID("_" + UUID.randomUUID().toString());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(Instant.now());
        response.setDestination(acsUrl);
        if (inResponseToId != null && !inResponseToId.isBlank()) {
            response.setInResponseTo(inResponseToId);
        }

        Issuer responseIssuer = create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        responseIssuer.setValue(samlIdpConfig.getEntityId());
        response.setIssuer(responseIssuer);

        Status status = create(Status.class, Status.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = create(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        Assertion assertion = buildAssertion(loginRequest, acsUrl, inResponseToId, audienceSpEntityId);
        signAssertion(assertion, keystoreService.getSigningCredential()); // Sign the assertion
        LOG.info("Assertion signed successfully.");
        response.getAssertions().add(assertion);

        String samlResponseXml = marshallObject(response);
        LOG.debug("Generated SAML Response XML: {}", samlResponseXml);

        return java.util.Base64.getEncoder().encodeToString(samlResponseXml.getBytes());
    }

    private Assertion buildAssertion(SamlLoginRequest loginRequest, String acsUrl, String inResponseToId, String audienceSpEntityId) {
        Assertion assertion = create(Assertion.class, Assertion.DEFAULT_ELEMENT_NAME);
        // Ensure the assertion has an ID for signature referencing
        if (assertion.getID() == null) {
            assertion.setID("assertion-" + UUID.randomUUID().toString());
        }
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssueInstant(Instant.now());

        Issuer assertionIssuer = create(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        assertionIssuer.setValue(samlIdpConfig.getEntityId());
        assertion.setIssuer(assertionIssuer);

        Subject subject = create(Subject.class, Subject.DEFAULT_ELEMENT_NAME);
        NameID nameID = create(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        nameID.setFormat(NameIDType.UNSPECIFIED);
        nameID.setValue(loginRequest.getUsername());
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = create(SubjectConfirmation.class, SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData subjectConfirmationData = create(SubjectConfirmationData.class, SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        subjectConfirmationData.setNotOnOrAfter(Instant.now().plusSeconds(300 * 60)); // 5 minutes validity (corrected to 5*60)
        subjectConfirmationData.setRecipient(acsUrl);
        if (inResponseToId != null && !inResponseToId.isBlank()) {
            subjectConfirmationData.setInResponseTo(inResponseToId);
        }
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);

        Conditions conditions = create(Conditions.class, Conditions.DEFAULT_ELEMENT_NAME);
        conditions.setNotBefore(Instant.now().minusSeconds(60));
        conditions.setNotOnOrAfter(Instant.now().plusSeconds(300 * 60)); // 5 minutes validity
        AudienceRestriction audienceRestriction = create(AudienceRestriction.class, AudienceRestriction.DEFAULT_ELEMENT_NAME);
        Audience audience = create(Audience.class, Audience.DEFAULT_ELEMENT_NAME);
        audience.setURI(audienceSpEntityId != null ? audienceSpEntityId : samlIdpConfig.getDefaultAcsUrl());
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);

        AuthnStatement authnStatement = create(AuthnStatement.class, AuthnStatement.DEFAULT_ELEMENT_NAME);
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setSessionIndex("session-" + UUID.randomUUID().toString());
        AuthnContext authnContext = create(AuthnContext.class, AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = create(AuthnContextClassRef.class, AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);

        if (loginRequest.getAttributes() != null && !loginRequest.getAttributes().isEmpty()) {
            AttributeStatement attributeStatement = create(AttributeStatement.class, AttributeStatement.DEFAULT_ELEMENT_NAME);
            for (Map.Entry<String, String> entry : loginRequest.getAttributes().entrySet()) {
                if (entry.getKey() == null || entry.getKey().isBlank() || entry.getValue() == null) continue;
                Attribute attribute = create(Attribute.class, Attribute.DEFAULT_ELEMENT_NAME);
                attribute.setName(entry.getKey());
                attribute.setNameFormat(Attribute.BASIC);
                org.opensaml.core.xml.schema.XSString attributeValue = (org.opensaml.core.xml.schema.XSString) builderFactory
                        .getBuilder(org.opensaml.core.xml.schema.XSString.TYPE_NAME)
                        .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, org.opensaml.core.xml.schema.XSString.TYPE_NAME);
                attributeValue.setValue(entry.getValue());
                attribute.getAttributeValues().add(attributeValue);
                attributeStatement.getAttributes().add(attribute);
            }
            if (!attributeStatement.getAttributes().isEmpty()) {
                assertion.getAttributeStatements().add(attributeStatement);
            }
        }
        return assertion;
    }

    private void signAssertion(Assertion assertion, Credential credential) throws SecurityException, MarshallingException, org.opensaml.xmlsec.signature.support.SignatureException {
        if (assertion.getID() == null) {
            assertion.setID("assertion-" + UUID.randomUUID().toString()); // Ensure ID for enveloped signature reference
            LOG.warn("Assertion ID was null before signing, generated new ID: {}", assertion.getID());
        }

        Signature signature = create(Signature.class, Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        // Explicitly generate and set KeyInfo
        if (credential instanceof X509Credential) {
            X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            // Configure what to include in KeyInfo. Emitting the certificate is common.
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            // keyInfoGeneratorFactory.setEmitPublicKeyValue(true); // Optionally include <KeyValue>
            // keyInfoGeneratorFactory.setEmitX509SubjectName(true); // Optionally include <X509SubjectName>

            try {
                KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
                KeyInfo keyInfo = keyInfoGenerator.generate((X509Credential) credential); // Cast is safe due to instanceof check
                signature.setKeyInfo(keyInfo);
                LOG.info("Explicitly generated and set KeyInfo including the entity certificate.");
            } catch (org.opensaml.security.SecurityException e) {
                LOG.error("Error generating KeyInfo for signature: {}", e.getMessage(), e);
                // This is a critical failure if KeyInfo is required or expected.
                throw new MarshallingException("Failed to generate KeyInfo for signature", e);
            }
        } else {
            LOG.warn("Signing credential is not an X509Credential (type: {}). " +
                     "Cannot explicitly generate X509 KeyInfo. " +
                     "Signer.signObject() might attempt to generate a default KeyInfo or the signature might lack it.",
                     credential != null ? credential.getClass().getName() : "null");
            // If KeyInfo is strictly required and this path is taken, signature validation might fail at SP.
        }

        assertion.setSignature(signature); // Set the Signature on the Assertion (enveloped signature)

        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion);
        if (marshaller == null) {
            throw new MarshallingException("Unable to get marshaller for Assertion object to prepare for signing.");
        }
        marshaller.marshall(assertion); // Marshall the Assertion to DOM. This includes the Signature structure (with KeyInfo).

        Signer.signObject(signature); // Now sign. This will populate DigestValue and SignatureValue.
    }

    @SuppressWarnings("unchecked")
    private <T extends XMLObject> T create(Class<T> cls, javax.xml.namespace.QName qname) {
        return (T) builderFactory.getBuilder(qname).buildObject(qname);
    }

    private String marshallObject(XMLObject xmlObject) throws MarshallingException {
        Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObject);
        if (marshaller == null) {
            throw new MarshallingException("Unable to get marshaller for XMLObject: " + xmlObject.getElementQName());
        }
        Element element = marshaller.marshall(xmlObject);
        return SerializeSupport.nodeToString(element);
    }
}