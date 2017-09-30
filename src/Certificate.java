import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
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

    public byte[] getBytes() {
        ByteBuffer ret = ByteBuffer.allocate(length + 10);
        ret.put((byte)HandshakeType.certificate.getMagicNumber());
        ret.put(CommonFunc.lengthToBytes(length+6));
        ret.put(CommonFunc.lengthToBytes(length));
        try {
            ret.put(CommonFunc.lengthToBytes(length));
            ret.put(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return ret.array();
    }
}
