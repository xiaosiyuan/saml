package com.bw.saml.cc.service;

import com.bw.saml.cc.pojo.AuthnRequestField;
import org.apache.commons.codec.binary.Base64;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * 处理saml request请求对象
 *
 * @author Xiaosy
 * @date 2017-12-14 13:53
 */
@Service
public class AuthnRequestHandler {
    /**
     * 解析saml request的base64字符串
     * @param encodedAuthnRequest base64加密过的字符串
     * @return
     */
    public AuthnRequestField handleAuthnRequest(String encodedAuthnRequest){
        String authnRequestXml = decode(encodedAuthnRequest);
        return readeAuthnRequest(authnRequestXml);
    }

    private AuthnRequestField readeAuthnRequest(String authnRequestXml){
        if(authnRequestXml == null){
            return null;
        }
        AuthnRequestField authnRequestField = new AuthnRequestField();
        Document doc = null;
        try {
            doc = DocumentHelper.parseText(authnRequestXml); // 将字符串转为XML
            Element rootElt = doc.getRootElement(); // 获取根节点
            String version = rootElt.attributeValue("Version");
            String ID = rootElt.attributeValue("ID");
            String destination = rootElt.attributeValue("Destination");
            String assertionCondumerServiceUrl = rootElt.attributeValue("AssertionConsumerServiceURL");
            String protocolBinding = rootElt.attributeValue("ProtocolBinding");
            Iterator<Element> elementIterator = rootElt.elementIterator();
            while (elementIterator.hasNext()){
                Element element = elementIterator.next();
                if("Issuer".equals(element.getName())){
                    authnRequestField.setSpIssuer(element.getTextTrim());
                    break;
                }
            }
            authnRequestField.setVersion(version);
            authnRequestField.setRequestId(ID);
            authnRequestField.setDestination(destination);
            authnRequestField.setAssertionConsumerServiceUrl(assertionCondumerServiceUrl);
            authnRequestField.setProtocolBinding(protocolBinding);
            return authnRequestField;

        } catch (DocumentException e) {
            e.printStackTrace();

        }
        return null;
    }

    /**
     * 解密请求参数
     * @param encSAMLRequest
     * @return
     */
    private String decode(String encSAMLRequest){
        String ret = null;

        //SamlRequest samlRequest = null; //the xml is compressed (deflate) and encoded (base64)
        byte[] decodedBytes = null;
        try {
            decodedBytes = new Base64().decode(encSAMLRequest.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            //try DEFLATE (rfc 1951) -- according to SAML spec
            ret = new String(inflate(decodedBytes, true));
            //return new SamlRequest(new String(inflate(decodedBytes, true)));
        } catch (Exception ze) {
            //try zlib (rfc 1950) -- initial impl didn't realize java docs are wrong
            try {
                System.out.println(new String(inflate(decodedBytes, false)));
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            //return new SamlRequest(new String(inflate(decodedBytes, false)));
        }
        return ret;
    }
    private byte[] inflate(byte[] bytes, boolean nowrap) throws Exception {

        Inflater decompressor = null;
        InflaterInputStream decompressorStream = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            decompressor = new Inflater(nowrap);
            decompressorStream = new InflaterInputStream(new ByteArrayInputStream(bytes),
                    decompressor);
            byte[] buf = new byte[1024];
            int count;
            while ((count = decompressorStream.read(buf)) != -1) {
                out.write(buf, 0, count);
            }
            return out.toByteArray();
        } finally {
            if (decompressor != null) {
                decompressor.end();
            }
            try {
                if (decompressorStream != null) {
                    decompressorStream.close();
                }
            } catch (IOException ioe) {
             /*ignore*/
                ioe.printStackTrace();
            }
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ioe) {
             /*ignore*/
                ioe.printStackTrace();
            }
        }
    }


    public static void main(String[] args) {
        String xml = "<AuthnRequest \n" +
                "\txmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" \n" +
                "\txmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \n" +
                "\tVersion=\"2.0\" \n" +
                "\tID=\"_4eb09fabb70c59648c89fbcdcec8032edbe095a355\" \n" +
                "\tIssueInstant=\"2017-12-12T02:18:47.583Z\" \n" +
                "\tDestination=\"https://xiaosy.onelogin.com/trust/saml2/http-post/sso/722531\" \n" +
                "\tAssertionConsumerServiceURL=\"https://bw30.worktile.com/api/sso/postback/5a2f38f7499e182113286d28\" \n" +
                "\tProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" > \n" +
                "\t<saml:Issuer>https://bw30.worktile.com/</saml:Issuer> \n" +
                "\t<NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\" AllowCreate=\"true\" /> \n" +
                "</AuthnRequest>";
        //System.out.println(readeAuthnRequest(xml));
    }
}
