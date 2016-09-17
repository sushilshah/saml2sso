package com.flex.twx.security.samlsso;

import java.util.HashMap;
import java.util.Map;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;


public class XMLhandler extends DefaultHandler {

	  class AuthResponse{
	        public String userName;
	        public String relayState;
	        public String X509Certificates;
	        public Map<String, String> attributes = new HashMap<>();
	    }
   
	  AuthResponse authResponse ;
	  boolean isNameID;
	  
    @Override
    public void startElement(String uri, String localName, String qName,
        Attributes attributes) throws SAXException {
    	
        //TODO Managing a LogoutRequest means that we have to build a LogoutResponse
        if(qName.equals("saml2:NameID")){
        	isNameID = true;
        	authResponse = new AuthResponse();
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName)
    		throws SAXException {
    	if(qName.equals("saml2:NameID")) isNameID = false;
    	
    }

    @Override
    public void characters(char[] ch, int start, int length) throws SAXException {
        if(isNameID){
        	String userName = new String(ch, start, length);
        	authResponse.userName = userName.split("@")[0];
        	System.out.println("AUTH USER NAME ");
        	System.out.println(authResponse.userName);
        }
        
    }

}