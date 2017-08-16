package eu.h2020.symbiote.security.communication.payloads;

public class RevocationRequest {


    private Credentials userCredentials = new Credentials();
    private Credentials adminCredentials = new Credentials();
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

    public Credentials getAdminCredentials() {
        return adminCredentials;
    }

    public void setAdminCredentials(Credentials adminCredentials) {
        this.credentialType = CredentialType.ADMIN;
        this.adminCredentials = adminCredentials;
    }

    public Credentials getUserCredentials() {
        return userCredentials;
    }

    public void setUserCredentials(Credentials userCredentials) {
        this.credentialType = CredentialType.USER;
        this.userCredentials = userCredentials;
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
