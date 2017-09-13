import com.sun.corba.se.impl.encoding.BufferManagerWriteGrow;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public class ServerHello {
    ProtocolVersion version;
    Random random;
    SessionID sessionID;
    CipherSuite cipherSuite;
    CompressionMethod compressionMethod;

    private final int RANDOM_SIZE = 32;

    public ServerHello() throws NoSuchAlgorithmException {
        version = new ProtocolVersion();
        random = new Random();
        sessionID = null;
        cipherSuite = new CipherSuite();
        compressionMethod = null;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public Random getRandom() {
        return random;
    }

    public SessionID getSessionID() {
        return sessionID;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public CompressionMethod getCompressionMethod() {
        return compressionMethod;
    }

    public byte[] getBytes() {
        ByteBuffer serverHello = ByteBuffer.allocate(38);
        serverHello.put(version.getMajor());
        serverHello.put(version.getMinor());
        serverHello.put(random.getRandom());

        if (sessionID == null)
            serverHello.put((byte)0x00);

        serverHello.putShort(cipherSuite.getCiphersuite());

        if (compressionMethod == null)
            serverHello.put((byte)0x00);

        return serverHello.array();
    }
}
