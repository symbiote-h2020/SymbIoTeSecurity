package eu.h2020.symbiote.security.commons.jwt;

import java.util.HashMap;
import java.util.Map;

/**
 * Placeholder for jwt claims
 *
 * @author Daniele Caldarola (CNIT)
 * @author Nemanja Ignjatov (UNIVIE)
 * @author Mikolaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */
public class JWTClaims {

    private String val;
    private String jti;
    private String alg;
    private String iss;
    private String sub;
    private Long iat;
    private Long exp;
    private String ipk;
    private String spk;
    private Map<String, String> att = new HashMap<>();
    private String ttyp;

    public JWTClaims() {
        // used by serializer
    }

    public JWTClaims(Map<String, Object> retMap, Map<String, String> att) {

        this.jti = (String) retMap.get("jti");
        this.alg = (String) retMap.get("alg");
        this.iss = (String) retMap.get("iss");
        this.sub = (String) retMap.get("sub");
        String stringToConvert = String.valueOf(retMap.get("iat"));
        this.iat = Long.parseLong(stringToConvert) * 1000;
        if (retMap.containsKey("exp")) {
            stringToConvert = String.valueOf(retMap.get("exp"));
            this.exp = Long.parseLong(stringToConvert) * 1000;
        }
        if (retMap.containsKey("val")) {
            this.val = (String) retMap.get("val");
        }
        this.ipk = (String) retMap.get("ipk");
        this.spk = (String) retMap.get("spk");
        this.att = att;
        this.ttyp = (String) retMap.get("ttyp");
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public String getIpk() {
        return ipk;
    }

    public void setIpk(String ipk) {
        this.ipk = ipk;
    }

    public String getSpk() {
        return spk;
    }

    public void setSpk(String spk) {
        this.spk = spk;
    }

    public Map<String, String> getAtt() {
        return att;
    }

    public void setAtt(Map<String, String> att) {
        this.att = att;
    }

    public String getVal() {
        return val;
    }

    public void setVal(String val) {
        this.val = val;
    }


    public String getTtyp() {
        return ttyp;
    }

    public void setTtyp(String ttyp) {
        this.ttyp = ttyp;
    }

    @Override
    public String toString() {
        return "JWTClaims{" +
                "jti='" + jti + '\'' +
                ", alg='" + alg + '\'' +
                ", iss='" + iss + '\'' +
                ", sub='" + sub + '\'' +
                ", iat='" + iat + '\'' +
                ", exp='" + exp + '\'' +
                ", val='" + val + '\'' +
                ", ipk='" + ipk + '\'' +
                ", spk='" + spk + '\'' +
                ", att='" + att + '\'' +
                ", ttyp'" + ttyp + '\'' +
                '}';
    }
}
