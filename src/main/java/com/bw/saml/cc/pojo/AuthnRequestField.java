package com.bw.saml.cc.pojo;

/**
 * 解析saml request后的参数
 *
 * @author Xiaosy
 * @date 2017-12-14 13:57
 */
public class AuthnRequestField {
    /**
     * 版本
     */
    private String version;
    /**
     * 请求的ID
     */
    private String requestId;
    /**
     * 目标url
     */
    private String destination;
    /**
     * acs地址，即SAMLResponse返回的目标地址
     */
    private String assertionConsumerServiceUrl;
    /**
     * 绑定方式
     */
    private String protocolBinding;
    /**
     * sp entityId
     */
    private String spIssuer;

    @Override
    public String toString() {
        return "AuthnRequestField{" +
                "version='" + version + '\'' +
                ", requestId='" + requestId + '\'' +
                ", destination='" + destination + '\'' +
                ", assertionConsumerServiceUrl='" + assertionConsumerServiceUrl + '\'' +
                ", protocolBinding='" + protocolBinding + '\'' +
                ", spIssuer='" + spIssuer + '\'' +
                '}';
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getAssertionConsumerServiceUrl() {
        return assertionConsumerServiceUrl;
    }

    public void setAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
    }

    public String getProtocolBinding() {
        return protocolBinding;
    }

    public void setProtocolBinding(String protocolBinding) {
        this.protocolBinding = protocolBinding;
    }

    public String getSpIssuer() {
        return spIssuer;
    }

    public void setSpIssuer(String spIssuer) {
        this.spIssuer = spIssuer;
    }
}
