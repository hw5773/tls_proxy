import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Certificate {
    int length;
    X509Certificate cert = null;
    FileInputStream fis = null;

    public Certificate() {
    }

    public void setCertificate(String fileName) {
        try {
            fis = new FileInputStream(new File(fileName));
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            cert = (X509Certificate) certificateFactory.generateCertificate(fis);
        } catch (FileNotFoundException e) {
            System.out.println("File Not Found");
            e.printStackTrace();
        } catch (CertificateException e) {
            System.out.println("Certificate Exception");
            e.printStackTrace();
        }finally {
            if (fis != null) try { fis.close(); } catch (IOException e) {}
        }

        try {
            length = cert.getEncoded().length;
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        System.out.println("length: " + length);
    }

    private static byte[] lengthToBytes(int length) {
        byte[] ret = new byte[3];
        ret[0] = (byte) ((length & 0x00ff0000) >> 16);
        ret[1] = (byte) ((length & 0x0000ff00) >> 8);
        ret[2] = (byte) (length & 0x000000ff);

        return ret;
    }

    public byte[] getBytes() {
        ByteBuffer ret = ByteBuffer.allocate(length + 3);
        ret.put(lengthToBytes(length));
        try {
            ret.put(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return ret.array();
    }
}
