package eu.h2020.symbiote.security.communication.payloads;

public class RevocationRequest {


    private Credentials credentials = new Credentials();
    private String homeTokenString = "";
    private String foreignTokenString = "";
    private String certificatePEMString = "";
    private String certificateCommonName = "";
    private CredentialType credentialType = CredentialType.NULL;

    public RevocationRequest() {
        //json required, all the required fields should be set using setters.
    }

    public CredentialType getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(CredentialType credentialType) {
        this.credentialType = credentialType;
    }

    public Credentials getCredentials() {
        return credentials;
    }

    public void setCredentials(Credentials credentials) {
        this.credentials = credentials;
    }

    public String getCertificateCommonName() {
        return certificateCommonName;
    }

    public void setCertificateCommonName(String certificateCommonName) {
        this.certificateCommonName = certificateCommonName;
    }

    public String getHomeTokenString() {
        return homeTokenString;
    }

    public void setHomeTokenString(String homeTokenString) {
        this.homeTokenString = homeTokenString;
    }

    public String getForeignTokenString() {
        return foreignTokenString;
    }

    public void setForeignTokenString(String foreignTokenString) {
        this.foreignTokenString = foreignTokenString;
    }

    public String getCertificatePEMString() {
        return certificatePEMString;
    }

    public void setCertificatePEMString(String certificatePEMString) {
        this.certificatePEMString = certificatePEMString;
    }

    public enum CredentialType {
        USER,
        ADMIN,
        NULL
    }
}
