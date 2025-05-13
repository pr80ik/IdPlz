package com.example.idplz.dto;

import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class SamlLoginRequest {
   private String username;
   private Map<String, String> attributes; // For simplicity, using String-String map
   private String samlRequest; // To hold the original SAMLRequest if needed
   private String relayState;  // To hold the RelayState if needed
   private String acsUrl; // To hold the SP's ACS URL
   private String requestId; // To hold the AuthnRequest ID
   private String spEntityId; // To hold the SP's Entity ID (for Audience)

}