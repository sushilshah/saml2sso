package com.flex.twx.security.samlsso;

import com.thingworx.logging.LogUtilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;
import org.apache.commons.codec.binary.Base64;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.slf4j.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

class SampleSAML2Utilities
{
  static final Logger logger = LogUtilities.getInstance().getApplicationLogger(SampleSAML2Utilities.class);
  private static ConcurrentHashMap<String, Date> _relayStateTokens = new ConcurrentHashMap();
  
  private static byte[] compress(byte[] data)
    throws IOException
  {
    Deflater deflater = new Deflater();
    deflater.setInput(data);
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    
    deflater.finish();
    byte[] buffer = new byte['?'];
    while (!deflater.finished())
    {
      int count = deflater.deflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    outputStream.close();
    byte[] output = outputStream.toByteArray();
    
    return output;
  }
  
  private static byte[] decompress(byte[] data)
    throws IOException, DataFormatException
  {
	  System.out.println("*** inside decompress");
    Inflater inflater = new Inflater(true);
    
    System.out.println("setInput");
    System.out.println(new String(data));
    //System.out.println(Arrays.toString(data));
    inflater.setInput(data);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(data.length);
    byte[] buffer = new byte['?'];
    System.out.println("start while loop");
    while (!inflater.finished())
    {
    	System.out.println("inflater.inflate ::: buffer:");
    	System.out.println(Arrays.toString(buffer));
      int count = inflater.inflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    System.out.println("outputStream close");
    outputStream.close();
    byte[] output = outputStream.toByteArray();
    
    return output;
  }
  
  static String createNewRelayState()
    throws Exception
  {
    String token = UUID.randomUUID().toString();
    _relayStateTokens.put(token, new Date());
    return token;
  }
  
  static void deleteNewRelayState(String relayState)
    throws Exception
  {
    _relayStateTokens.remove(relayState);
  }
  
  static boolean isRelayStateValid(String relayState)
  {
    boolean isValid = false;
    isValid = _relayStateTokens.containsKey(relayState);
    return isValid;
  }
  
  static String generateSAMLRequest(String providerName, String acsURL)
    throws Exception
  {
    String samlRequest = null;
    
    String id = "_" + UUID.randomUUID().toString();
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    Date currentDate = new Date();
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    XMLOutputFactory factory = XMLOutputFactory.newInstance();
    
    XMLStreamWriter writer = factory.createXMLStreamWriter(baos);
    
    writer.writeStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol");
    writer.writeNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
    
    writer.writeAttribute("ID", id);
    writer.writeAttribute("Version", "2.0");
    writer.writeAttribute("IssueInstant", df.format(currentDate));
    writer.writeAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    writer.writeAttribute("AssertionConsumerServiceURL", acsURL);
    
    writer.writeStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion");
    writer.writeNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
    writer.writeCharacters(providerName);
    writer.writeEndElement();
    
    writer.writeStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol");
    writer.writeAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
    writer.writeAttribute("AllowCreate", "true");
    writer.writeEndElement();
    
    writer.writeEndElement();
    
    writer.flush();
    
    samlRequest = encode(baos.toByteArray());
    
    return samlRequest;
  }
  
  private static String encode(byte[] unencodedSamlRequest)
    throws Exception
  {
    byte[] compressedSamlRequest = compress(unencodedSamlRequest);

    Base64 base64Encoder = new Base64();
    String base64EncodedRequest = new String(base64Encoder.encode(compressedSamlRequest));
    String urlEncodedRequest = URLEncoder.encode(base64EncodedRequest, "UTF-8");
    
    return urlEncodedRequest;
  }
  
  static SampleSAML2ResponseData getSAMLResponseData(HttpServletRequest httpRequest)
    throws Exception
  {
	  String responseMessage = httpRequest.getParameter("SAMLResponse").toString(); 
	  
	  String inflatedSamlResponse = null ;
	  /*DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
	  documentBuilderFactory.setNamespaceAware(true);
	  DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();*/
	  byte[] base64DecodedResponse = null ;
	  try {
		
		  base64DecodedResponse = org.opensaml.xml.util.Base64.decode(responseMessage);
	} catch (Exception e) {
		System.err.println("###Cannot decode ");
		e.printStackTrace();
	}
	  
	  System.out.println("decompress(base64DecodedResponse)");
	  System.out.println(new String(base64DecodedResponse));
	  
	  ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
	 /* Document document = docBuilder.parse(is);
	  Element element = document.getDocumentElement();*/
	/*  UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
	  Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
	  Response response = (Response) unmarshaller.unmarshall(element);*/
	  /*
	  System.out.println("***inside getSAMLResponseData");
    String urlEncodedSamlResponse = getEncodedSAMLResponse(httpRequest);
    String urlDecodedSamlResponse = URLDecoder.decode(urlEncodedSamlResponse, "UTF-8");
    byte[] base64DecodedSamlResponse = Base64.decodeBase64(urlDecodedSamlResponse);
    System.out.println("decompress(base64DecodedSamlResponse)");
    System.out.println(new String(base64DecodedSamlResponse));
   
    try{
    	byte[] inflatedSamlResponseByteArray = decompress(base64DecodedSamlResponse);
    	inflatedSamlResponse = new String(inflatedSamlResponseByteArray);	
    }catch(Exception e){
    	System.out.println("******** Exception occured ");
    	System.out.println(e);
    	e.printStackTrace();
    }
    
    
    System.out.println("***return getSAMLResponseData");*/
    return null; //parseSAMLResponse(inflatedSamlResponse);
  }
  
  private static SampleSAML2ResponseData parseSAMLResponse(String decodedSAMLResponse)
  {
	  System.out.println("*** start parseSAMLResponse");
    SampleSAML2ResponseData d = new SampleSAML2ResponseData();
    try
    {
      DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = dbFactory.newDocumentBuilder();
      InputSource is = new InputSource(new StringReader(decodedSAMLResponse));
      Document doc = builder.parse(is);
      
      Element element = doc.getDocumentElement();
      
      NodeList nl = element.getElementsByTagName("saml:Subject");
      if ((nl != null) && (nl.getLength() > 0))
      {
        Element el = (Element)nl.item(0);
        
        NodeList nl2 = el.getElementsByTagName("saml:NameID");
        if ((nl2 != null) && (nl2.getLength() > 0))
        {
          Element el2 = (Element)nl2.item(0);
          d.userName = el2.getTextContent();
        }
      }
    }
    catch (Exception e)
    {
      logger.error("An error occurred parsing the SAML Response: " + e.getMessage());
      System.out.println("An error occurred parsing the SAML Response: " + e.getMessage());
    }
    System.out.println("return parseSAMLResponse");
    return d;
  }
  
  static String getEncodedSAMLResponse(HttpServletRequest httpRequest)
  {
    String encodedSamlResponse = null;
    Map<String, String[]> paramMap = httpRequest.getParameterMap();
    String[] sra = (String[])paramMap.get("SAMLResponse");
    if (sra != null) {
      encodedSamlResponse = sra[0];
    }
    /*encodedSamlResponse = httpRequest.getParameter("SAMLResponse").toString();
    System.out.println("*** encodedSamlResponse : " + encodedSamlResponse);*/
    return encodedSamlResponse;
  }
  
  static String getRelayState(HttpServletRequest httpRequest)
  {
    String relayState = null;
    Map<String, String[]> paramMap = httpRequest.getParameterMap();
    String[] rs = (String[])paramMap.get("RelayState");
    if (rs != null) {
      relayState = rs[0];
    }
    return relayState;
  }
  
  static class SampleSAML2ResponseData
  {
    String userName;
  }
}

