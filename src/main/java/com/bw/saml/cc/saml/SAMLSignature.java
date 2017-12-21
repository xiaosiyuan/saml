package com.bw.saml.cc.saml;


import com.bw.saml.cc.security.KeyStoreUtil;
import com.bw.saml.cc.xml.PrettyPrinter;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.SignatureConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;


/**
Utility for signing SAML DOM objects (assertions, requests, and responses)
and for validating and checking signatures on SAML DOM objects.
Unlike the rest of this package, this utility does not rely on OpenSAML;
it operates directly on DOM trees.  (There is an import of OpenSAML's
XMLObject type, but that's just for our main method, which in turn is just
for testing purposes.)

@author Will Provost
*/
/*
Copyright 2009 Will Provost.  
All rights reserved by Capstone Courseware, LLC.
*/
public class SAMLSignature
{
    private XMLSignatureFactory factory;
    private KeyStore keyStore;
    private KeyPair keyPair;
    private KeyInfo keyInfo;
    private BasicX509Credential credential;
    
    /**
    Parse the command line for a filename to read, and optionally a filename
    to write (absent which the application will write to the console).
    Reads the given file as an XMLObject, signs it using the configured key,
    and then dumps using a simple {@link cc.xml.PrettyPrinter pretty printer}.
    Or, validates the signature found in the given file.
    */
    public static void main (String[] args)
        throws Exception
    {
        if (args.length < 2)
        {
            System.out.println ("Usage: java cc.saml.SAMLSignature " + 
                "sign|verify <inputFile> [<outputBaseName>]");
            System.exit (-1);
        }
        
        String command = args[0];
        String inputFilename = args[1];
        
        if (command.equals ("sign"))
        {
            if (args.length < 3)
            {
                System.out.println ("Usage: java cc.saml.SAML " + 
                    "sign <inputFile> <outputBaseName>");
                System.exit (-1);
            }
            
            String baseName = args[2];

            SAML utility = new SAML ();        
            SAMLSignature signature = new SAMLSignature ();

            XMLObject root = utility.readFromFile (inputFilename);
            Document doc = utility.asDOMDocument (root);
            Element target = doc.getDocumentElement ();

            signature.signSAMLObject (target);
            signature.writeFiles (doc, baseName);
        }
        else if (command.equals ("verify"))
        {
            SAML utility = new SAML ();        
            SAMLSignature signature = new SAMLSignature ();

            XMLObject root = utility.readFromFile (inputFilename);
            Document doc = utility.asDOMDocument (root);
            Element target = doc.getDocumentElement ();
            
            if (signature.verifySAMLSignature (target))
                System.out.println("Signature passed validation.");
            else
                System.out.println("Signature failed validation!");
        }
        else
        {
            System.out.println ("Usage: java cc.saml.SAML " + 
                "sign|verify <inputFile> [<outputBaseName>]");
            System.exit (-1);
        }
    }
        
    /**
    Loads a keystore and builds a stock key-info structure for use by 
    base classes.
    */
    public SAMLSignature ()
    {
        try
        {
            Properties props = new Properties ();
            props.load (SAMLSignature.class.getResourceAsStream 
                ("/security.properties"));
            
            /*String providerName = System.getProperty
                ("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
            factory = XMLSignatureFactory.getInstance ("DOM", 
                (Provider) Class.forName (providerName).newInstance ());*/
            factory = XMLSignatureFactory.getInstance();

            keyStore = KeyStoreUtil.getKeyStore
                (SAMLSignature.class.getResourceAsStream 
                    (props.getProperty ("keystore")), 
                 props.getProperty ("storepass"));
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)
                keyStore.getEntry (props.getProperty ("alias"), 
                    new KeyStore.PasswordProtection 
                        (props.getProperty ("keypass").toCharArray ()));
            keyPair = new KeyPair (entry.getCertificate ().getPublicKey (), 
                entry.getPrivateKey ());

            KeyInfoFactory kFactory = factory.getKeyInfoFactory ();
            keyInfo = kFactory.newKeyInfo 
                (Collections.singletonList (kFactory.newX509Data 
                    (Collections.singletonList (entry.getCertificate ()))));
            X509Certificate certificate = (X509Certificate) entry.getCertificate();
            credential = new BasicX509Credential();
            credential.setEntityCertificate(certificate);
            credential.setPrivateKey(entry.getPrivateKey());
        }
        catch (Exception ex)
        {
            ex.printStackTrace ();
        }
    }
    
    /**
    Adds an enveloped signature to the given element.
    Then moves the signature element so that it is in the correct position
    according to the SAML assertion and protocol schema: it must immediately 
    follow any Issuer and precede everything else.
    */
    public void signSAMLObject (Element target)
        throws GeneralSecurityException, XMLSignatureException, MarshalException 
    {
        Reference ref = factory.newReference
            ("#" + target.getAttribute ("ID"),
             factory.newDigestMethod (SignatureConstants.ALGO_ID_DIGEST_SHA1, null),
             Collections.singletonList (factory.newTransform
                (SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE, (TransformParameterSpec) null)),
             null, 
             null);

        SignedInfo signedInfo = factory.newSignedInfo 
            (factory.newCanonicalizationMethod
                (SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                    (C14NMethodParameterSpec) null), 
                 factory.newSignatureMethod (SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, null),
                 Collections.singletonList (ref));

        XMLSignature signature = factory.newXMLSignature (signedInfo, keyInfo);
        DOMSignContext signContext = new DOMSignContext
            (keyPair.getPrivate (), target);
        signContext.setDefaultNamespacePrefix("ds");
        signContext.setIdAttributeNS(target,null,"ID");
        signature.sign (signContext);


        // For the result to be schema-valid, we have to move the signature
        // element from its place at the end of the child list to live
        // between Issuer and Subject elements.  So, deep breath, and:
        Node signatureElement = target.getLastChild ();

        boolean foundIssuer = false;
        Node elementAfterIssuer = null;
        NodeList children = target.getChildNodes ();
        for (int c = 0; c < children.getLength (); ++c)
        {
            Node child = children.item (c);
            
            if (foundIssuer)
            {
                elementAfterIssuer = child;
                break;
            }
            
            if (child.getNodeType () == Node.ELEMENT_NODE &&
                    child.getLocalName ().equals ("Issuer"))
                foundIssuer = true;
        }
        
        // Place after the Issuer, or as first element if no Issuer:
        if (!foundIssuer || elementAfterIssuer != null)
        {
            target.removeChild (signatureElement);
            target.insertBefore (signatureElement, 
                foundIssuer
                    ? elementAfterIssuer
                    : target.getFirstChild ());
        }
    }

    public void signSAMLObject (Document doc,String referenceId,Node signNode)
            throws GeneralSecurityException, XMLSignatureException, MarshalException {
        List transforms = new ArrayList(2);
        transforms.add(factory.newTransform
                (SignatureConstants.TRANSFORM_ENVELOPED_SIGNATURE, (TransformParameterSpec) null));
        transforms.add(factory.newTransform
                (SignatureConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (TransformParameterSpec) null));
        Reference ref = factory.newReference
                ("#" + referenceId,
                        factory.newDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA1, null),
                        transforms,
                        null,
                        null);
        SignedInfo signedInfo = factory.newSignedInfo
                (factory.newCanonicalizationMethod
                                (SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                                        (C14NMethodParameterSpec) null),
                        factory.newSignatureMethod(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, null),
                        Collections.singletonList(ref));

        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo);
        DOMSignContext signContext = new DOMSignContext
                (keyPair.getPrivate(), signNode);
        //signContext.setDefaultNamespacePrefix("ds");
        Element element = (Element) doc.getElementsByTagName("saml:Assertion").item(0);
        element.setIdAttribute("ID", true);
        signContext.setIdAttributeNS(element, null, "ID");
        signature.sign(signContext);

        Node signatureElement = signNode.getLastChild ();

        boolean foundIssuer = false;
        Node elementAfterIssuer = null;
        NodeList children = signNode.getChildNodes ();
        for (int c = 0; c < children.getLength (); ++c)
        {
            Node child = children.item (c);

            if (foundIssuer)
            {
                elementAfterIssuer = child;
                break;
            }

            if (child.getNodeType () == Node.ELEMENT_NODE &&
                    child.getLocalName ().equals ("Issuer"))
                foundIssuer = true;
        }

        // Place after the Issuer, or as first element if no Issuer:
        if (!foundIssuer || elementAfterIssuer != null)
        {
            signNode.removeChild (signatureElement);
            signNode.insertBefore (signatureElement,
                    foundIssuer
                            ? elementAfterIssuer
                            : signNode.getFirstChild ());
        }
    }


    public void signAssertion(SignableXMLObject obj) {

        org.opensaml.xml.signature.Signature signature = (org.opensaml.xml.signature.Signature) Configuration.getBuilderFactory()
                .getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME).buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);

        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        try {
            SecurityHelper.prepareSignatureParams(signature, credential, secConfig, null);
            obj.setSignature(signature);
            Configuration.getMarshallerFactory().getMarshaller(obj).marshall(obj);
            org.opensaml.xml.signature.Signer.signObject(signature);
        } catch (Exception e) {
            System.out.println("Can't prepare signature");
        }
    }


    /**
    Seeks out the signature element in the given tree, and validates it.
    Searches the configured keystore (asking it to function also as a
    truststore) for a certificate with a matching fingerprint.
    
    @return true if the signature validates and we know the signer; 
            false otherwise
    */
    public boolean verifySAMLSignature (Element target)
        throws Exception
    {
        // Validate the signature -- i.e. SAML object is pristine:
        NodeList nl = 
            target.getElementsByTagNameNS (XMLSignature.XMLNS, "Signature");
        if (nl.getLength () == 0) 
            throw new Exception ("Cannot find Signature element");

        DOMValidateContext context = new DOMValidateContext
            (new KeyValueKeySelector (), nl.item (0));
        Element element = (Element) target.getElementsByTagName("saml:Assertion").item(0);
        element.setIdAttribute("ID", true);
        context.setIdAttributeNS(element, null, "ID");

        XMLSignature signature = factory.unmarshalXMLSignature (context);
        if (!signature.validate (context)){
            System.out.println("失败");
            return false;
        }

        
        // Find a trusted cert -- i.e. the signer is actually someone we trust:
        for (Object keyInfoItem : signature.getKeyInfo ().getContent ())
          if (keyInfoItem instanceof X509Data)
            for (Object X509Item : ((X509Data) keyInfoItem).getContent ())
              if (X509Item instanceof X509Certificate)
              {
                X509Certificate theirCert = (X509Certificate) X509Item;

                @SuppressWarnings ("unchecked")
                List<String> aliases = KeyStoreUtil.getAliases (keyStore);
                
                for (String alias : aliases)
                {
                  Certificate ourCert = 
                      KeyStoreUtil.getCertificate (keyStore, alias);
                  if (ourCert.equals (theirCert))
                    return true;
                }
              }
        
        System.out.println ("Signature was valid, but signer was not known.");
        return false;
    }

    /**
    KeySelector that can handle KeyValue and X509Data info.
    */
    private static class KeyValueKeySelector 
        extends KeySelector 
    {
        public KeySelectorResult select(KeyInfo keyInfo, 
            Purpose purpose, AlgorithmMethod method,
                XMLCryptoContext context)
            throws KeySelectorException 
        {
            if (keyInfo == null) 
                throw new KeySelectorException ("Null KeyInfo object!");

            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent ();

            for (int i = 0; i < list.size(); i++) 
            {
                XMLStructure xmlStructure = (XMLStructure) list.get (i);
                PublicKey pk = null;
                try 
                {
                    if (xmlStructure instanceof KeyValue) 
                        pk = ((KeyValue) xmlStructure).getPublicKey ();
                    else if (xmlStructure instanceof X509Data) 
                    {
                        for (Object data : 
                                ((X509Data) xmlStructure).getContent ())
                            if (data instanceof X509Certificate)
                                pk = ((X509Certificate) data).getPublicKey ();
                    }
                }
                catch (KeyException ke) 
                {
                    throw new KeySelectorException(ke);
                }
                    
                if (algEquals (sm.getAlgorithm (), pk.getAlgorithm ())) 
                    return new SimpleKeySelectorResult (pk);
            }
            
            throw new KeySelectorException ("No KeyValue element found!");
        }
    }

    /**
    Test that a formal URI expresses the same algorithm as a conventional
    short name such as "DSA" or "RSA".
    */
    static boolean algEquals (String algURI, String algName) 
    {
        return (algName.equalsIgnoreCase ("DSA") &&
                algURI.equalsIgnoreCase (SignatureMethod.DSA_SHA1)) 
            ||
               (algName.equalsIgnoreCase ("RSA") &&
                algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1));
    }

    /**
    Data structure returned by the key selector to the validation context.
    */
    private static class SimpleKeySelectorResult 
        implements KeySelectorResult 
    {
        private PublicKey pk;
        
        SimpleKeySelectorResult (PublicKey pk) 
        {
            this.pk = pk;
        }

        public Key getKey() 
        { 
            return pk; 
        }
    }

    /**
    Helper method to write two output files from a given DOM tree:
    one is the raw output and one is pretty-printed and given the suffix
    "_pretty" before the ".xml" extension.
    */
    public void writeFiles (Document doc, String baseFilename)
        throws IOException
    {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream ();

        try
        {
            TransformerFactory.newInstance ().newTransformer()
                .transform (new DOMSource (doc), new StreamResult (buffer));

            byte[] rawResult = buffer.toByteArray ();
            buffer.close ();
        
            OutputStream rawOutput = 
                new FileOutputStream (baseFilename + ".xml");
            rawOutput.write (rawResult);
            rawOutput.write 
                (System.getProperty ("line.separator").getBytes ());
            rawOutput.close ();

            String prettyResult = PrettyPrinter.prettyPrint (rawResult);
            PrintWriter prettyOutput = new PrintWriter 
                (new FileWriter (baseFilename + "_pretty.xml"));
            prettyOutput.println (prettyResult);
            prettyOutput.close ();
        }
        catch (TransformerException ex)
        {
            ex.printStackTrace ();
        }
    }
}
