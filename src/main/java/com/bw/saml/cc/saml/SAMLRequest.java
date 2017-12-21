package com.bw.saml.cc.saml;

import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.w3c.dom.Document;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.util.UUID;

/**
 * @author Xiaosy
 * @date 2017-12-14 15:34
 */
public class SAMLRequest extends SAML {

    /**
     * 创建authnrequest xml 字符串
     * @param idpSsoUrl
     * @param acsUrl
     * @param spEntityId
     * @return
     * @throws Exception
     */
    public String createRequestXmlString(String idpSsoUrl,String acsUrl,String spEntityId) throws Exception {
        AuthnRequest authnRequest = createRequest(idpSsoUrl,acsUrl,spEntityId);
        Document document = asDOMDocument(authnRequest);
        DOMSource source=new DOMSource(document);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer former=tf.newTransformer();
        former.setOutputProperty(OutputKeys.STANDALONE, "yes");
        StringWriter sw = new StringWriter();
        StreamResult sr = new StreamResult(sw);
        former.transform(source, sr);
        String result=sw.toString();
        return result;
    }

    /**
     * 创建AutheRequest对象
     * @param idpSsoUrl
     * @param acsUrl
     * @param spEntityId
     * @return
     */
    public AuthnRequest createRequest(String idpSsoUrl,String acsUrl,String spEntityId){
        AuthnRequest authnRequest = create(AuthnRequest.class,AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setIssueInstant(new DateTime());
        authnRequest.setDestination(idpSsoUrl);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authnRequest.setID(UUID.randomUUID().toString());
        authnRequest.setAssertionConsumerServiceURL(acsUrl);

        Issuer issuer = create(Issuer.class,Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(spEntityId);
        authnRequest.setIssuer(issuer);

        NameIDPolicy nameIDPolicy = create(NameIDPolicy.class,NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameID.UNSPECIFIED);
        authnRequest.setNameIDPolicy(nameIDPolicy);
        return authnRequest;
    }
}
