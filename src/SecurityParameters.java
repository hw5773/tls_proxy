import java.security.cert.X509Certificate;
import java.util.Random;

/**
 * Created by HWY on 2017-07-11.
 */

public class SecurityParameters {
    private long sessionID;
    private X509Certificate peerCertificate;
    private short compressionMethod;
    private CipherSuite cs;
    private byte[] masterSecret;
    private byte[] clientRandom;
    private byte[] serverRandom;
    private boolean isResumable = false;

    public SecurityParameters() {
        cs = new CipherSuite();
    }

    public void setClientRandom(byte[] cr) {
        clientRandom = cr;
    }

    public void setServerRandom(byte[] sr) {
        serverRandom = sr;
    }

    public CipherSuite getCipherSuite() {
        return cs;
    }
}
