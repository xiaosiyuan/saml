package com.bw.saml.idp;

import org.springframework.stereotype.Service;

/**
 * @author Xiaosy
 * @date 2017-12-21 10:44
 */
@Service
public class SamlRequestCache {

    private String SAMLRequest;

    public String getSAMLRequest() {
        return SAMLRequest;
    }

    public void setSAMLRequest(String SAMLRequest) {
        this.SAMLRequest = SAMLRequest;
    }
}
