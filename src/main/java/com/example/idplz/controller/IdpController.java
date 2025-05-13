package com.example.idplz.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.example.idplz.config.SamlIdpConfig;
import com.example.idplz.dto.SamlLoginRequest;
import com.example.idplz.service.SamlResponseGenerator;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.DecodingException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;


@Controller
public class IdpController {

   private static final Logger LOG = LoggerFactory.getLogger(IdpController.class);
   private final SamlResponseGenerator samlResponseGenerator;
   private final SamlIdpConfig samlIdpConfig;
   private BasicParserPool parserPool;


   public IdpController(SamlResponseGenerator samlResponseGenerator, SamlIdpConfig samlIdpConfig) {
       this.samlResponseGenerator = samlResponseGenerator;
       this.samlIdpConfig = samlIdpConfig;
       // Initialize ParserPool for parsing SAMLRequest
       this.parserPool = new BasicParserPool();
       try {
           this.parserPool.initialize();
       } catch (ComponentInitializationException e) {
           LOG.error("Failed to initialize ParserPool", e);
           throw new RuntimeException("Failed to initialize XML parser pool", e);
       }
   }

   // Entry point for SP-initiated SSO (HTTP-Redirect or HTTP-POST)
   @RequestMapping(value = "/saml/sso") // Handles both GET (Redirect) and POST
   public String handleSsoRequest(@RequestParam(name = "SAMLRequest", required = false) String samlRequestB64,
                                  @RequestParam(name = "RelayState", required = false) String relayState,
                                  HttpServletRequest request,
                                  Model model) {
       LOG.info("Received SAML SSO request. SAMLRequest present: {}, RelayState: {}", samlRequestB64 != null, relayState);

       SamlLoginRequest loginRequest = SamlLoginRequest.builder().username("user@example.com").build();
       loginRequest.setRelayState(relayState);

       if (samlRequestB64 != null) {
           try {
               String samlRequestXml;
               // Handle HTTP-Redirect binding (DEFLATE + Base64)
               if (request.getMethod().equalsIgnoreCase("GET")) {
                   LOG.debug("Processing SAMLRequest with HTTP-Redirect binding.");
                   byte[] decodedBytes = Base64Support.decode(samlRequestB64);
                   Inflater inflater = new Inflater(true); // true for "nowrap" (no zlib header/checksum)
                   ByteArrayInputStream bis = new ByteArrayInputStream(decodedBytes);
                   InputStream iis = new InflaterInputStream(bis, inflater);
                   // iis = bis; //TODO: maybe not ziped?
                   samlRequestXml = new String(iis.readAllBytes(), StandardCharsets.UTF_8);
                   LOG.debug("Decoded and Inflated SAMLRequest XML (Redirect): {}", samlRequestXml);

               }
               // Handle HTTP-POST binding (Base64 only)
               else if (request.getMethod().equalsIgnoreCase("POST")) {
                   LOG.debug("Processing SAMLRequest with HTTP-POST binding.");
                   samlRequestXml = new String(Base64Support.decode(samlRequestB64), StandardCharsets.UTF_8);
                   LOG.debug("Decoded SAMLRequest XML (POST): {}", samlRequestXml);
               } else {
                   LOG.warn("Unsupported HTTP method for SAMLRequest: {}", request.getMethod());
                   model.addAttribute("errorMessage", "Unsupported HTTP method.");
                   return "error"; // Or an appropriate error view
               }

               loginRequest.setSamlRequest(samlRequestXml); // Store the raw XML if needed later

               // Parse the SAMLRequest XML to get ACS URL, Request ID, SP Entity ID
               AuthnRequest authnRequest = parseAuthnRequest(samlRequestXml);
               if (authnRequest != null) {
                   loginRequest.setAcsUrl(authnRequest.getAssertionConsumerServiceURL());
                   loginRequest.setRequestId(authnRequest.getID());
                   if (authnRequest.getIssuer() != null) {
                       loginRequest.setSpEntityId(authnRequest.getIssuer().getValue());
                   }
                   LOG.info("Parsed AuthnRequest - ACS: {}, ID: {}, Issuer: {}",
                           loginRequest.getAcsUrl(), loginRequest.getRequestId(), loginRequest.getSpEntityId());
               } else {
                   LOG.warn("Failed to parse AuthnRequest. Using default ACS if available.");
                   loginRequest.setAcsUrl(samlIdpConfig.getDefaultAcsUrl()); // Fallback
               }

           } catch (IOException | UnmarshallingException | net.shibboleth.utilities.java.support.xml.XMLParserException | DecodingException e) {
               LOG.error("Error processing SAMLRequest: {}", e.getMessage(), e);
               model.addAttribute("errorMessage", "Invalid SAMLRequest: " + e.getMessage());
               loginRequest.setAcsUrl(samlIdpConfig.getDefaultAcsUrl()); // Fallback on error
               // return "error"; // Or an appropriate error view
           }
       } else {
           // IdP-initiated login or direct access to login page
           LOG.info("No SAMLRequest found, preparing for IdP-initiated or direct login.");
           // For IdP-initiated, ACS URL must be known or pre-configured. Using default.
           loginRequest.setAcsUrl(samlIdpConfig.getDefaultAcsUrl());
       }

       model.addAttribute("samlLoginRequest", loginRequest);
       // Add a default attribute for the UI
       if (loginRequest.getAttributes() == null || loginRequest.getAttributes().isEmpty()) {
           Map<String, String> defaultAttrs = new HashMap<>();
           defaultAttrs.put("email", "user@example.com");
           defaultAttrs.put("firstName", "Jane");
           defaultAttrs.put("lastName", "Doe");
           loginRequest.setAttributes(defaultAttrs);
       }
       return "login";
   }


   private AuthnRequest parseAuthnRequest(String samlRequestXml) throws UnmarshallingException, net.shibboleth.utilities.java.support.xml.XMLParserException {
	   LOG.debug("samlRequestXml: {}", new String(samlRequestXml.getBytes()));
       ByteArrayInputStream is = new ByteArrayInputStream(samlRequestXml.getBytes(StandardCharsets.UTF_8));
       Document doc = parserPool.parse(is);
       Element authnRequestElement = doc.getDocumentElement();

       UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
       Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(authnRequestElement);
       if (unmarshaller == null) {
           LOG.error("No unmarshaller found for AuthnRequest element: {}", authnRequestElement.getTagName());
           return null;
       }
       XMLObject xmlObject = unmarshaller.unmarshall(authnRequestElement);
       if (xmlObject instanceof AuthnRequest) {
           return (AuthnRequest) xmlObject;
       } else {
           LOG.error("Parsed XMLObject is not an instance of AuthnRequest: {}", xmlObject.getClass().getName());
           return null;
       }
   }


   @PostMapping("/saml/reply")
   public void processLogin(@ModelAttribute SamlLoginRequest samlLoginRequest, HttpServletResponse response) throws IOException {
       LOG.info("Processing login submission for user: {}", samlLoginRequest.getUsername());
       LOG.info("Attributes: {}", samlLoginRequest.getAttributes());
       LOG.info("Target ACS URL: {}", samlLoginRequest.getAcsUrl());
       LOG.info("InResponseTo (AuthnRequest ID): {}", samlLoginRequest.getRequestId());
       LOG.info("SP Entity ID (Audience): {}", samlLoginRequest.getSpEntityId());


       // Determine ACS URL and InResponseTo from the carried forward SamlLoginRequest
       String acsUrl = samlLoginRequest.getAcsUrl();
       if (acsUrl == null || acsUrl.isBlank()) {
           LOG.warn("ACS URL is missing in login submission, using default: {}", samlIdpConfig.getDefaultAcsUrl());
           acsUrl = samlIdpConfig.getDefaultAcsUrl(); // Fallback, should ideally come from AuthnRequest
       }
       String inResponseToId = samlLoginRequest.getRequestId();
       String spEntityId = samlLoginRequest.getSpEntityId(); // This is crucial for AudienceRestriction

       try {
           String samlResponseBase64 = samlResponseGenerator.generateSamlResponse(
                   samlLoginRequest,
                   acsUrl,
                   acsUrl, // Recipient is typically the ACS URL
                   inResponseToId,
                   spEntityId // Pass SP entity ID for Audience
           );

           // Send the SAML Response back to the SP via HTTP-POST (auto-submit form)
           response.setContentType("text/html");
           PrintWriter out = response.getWriter();
           out.println("<html><body onload=\"document.forms[0].submit()\">");
           out.println("<form method=\"POST\" action=\"" + acsUrl + "\">");
           out.println("<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + samlResponseBase64 + "\"/>");
           if (samlLoginRequest.getRelayState() != null && !samlLoginRequest.getRelayState().isEmpty()) {
               out.println("<input type=\"hidden\" name=\"RelayState\" value=\"" + samlLoginRequest.getRelayState() + "\"/>");
           }
           out.println("<noscript><p>Script is disabled. Click Submit to continue.</p><input type=\"submit\" value=\"Submit\"/></noscript>");
           out.println("</form></body></html>");
           out.flush();
           LOG.info("SAML Response sent to SP at ACS URL: {}", acsUrl);

       } catch (Exception e) {
           LOG.error("Error generating or sending SAML Response: {}", e.getMessage(), e);
           response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error generating SAML response: " + e.getMessage());
       }
   }
}