import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.text.SimpleDateFormat;

public class ServerTest {
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private final static int RANDOM_SIZE = 32;
	private static SecurityParameters sp;
	private static MessageDigest md;
	private static String certFile = "C:\\Users\\HWY\\Documents\\intelliJ\\tls_handshake\\src\\alice_cert.pem";

	public static void main(String[] args) throws IOException {
		sp = new SecurityParameters();
		ServerSocket serverSocket = null;
		int port = 5555;

		try {
			serverSocket = new ServerSocket(port);
			System.out.println(getTime() + " 서버가 준비되었습니다.");

			Socket socket = serverSocket.accept();
			InetAddress clientAddress = socket.getInetAddress();
			System.out.println(getTime() + clientAddress + " 에서 클라이언트가 접속했습니다.");

			OutputStream os = socket.getOutputStream();
			InputStream is = socket.getInputStream();

			ByteArrayOutputStream buffer = new ByteArrayOutputStream();

			int nRead, nWrite;
			byte[] data = new byte[16384];

			while (true) {
				nRead = is.read(data);
				System.out.println("nRead: " + nRead);
				if (nRead < 0)
					break;
				byte[] clientHello = toBytes(data, nRead);
				parseRecord(clientHello);
				byte[] serverHello = makeRecord(HandshakeType.server_hello);
				os.write(serverHello);
				byte[] certificate = makeRecord(HandshakeType.certificate);
				bytesToHex(certificate, certificate.length);
				os.write(certificate);
				byte[] serverHelloDone = makeRecord(HandshakeType.server_hello_done);
				//os.write(serverHelloDone);

				//nRead = is.read(data);
				//System.out.println("nRead: " + nRead);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] toBytes(byte[] data, int nRead) {
		byte[] ret = new byte[nRead];
		System.arraycopy(data, 0, ret, 0, nRead);

		return ret;
	}

	private static void bytesToHex(byte[] bytes, int nRead) {
		char[] hexChars = new char[nRead * 2];
		for (int i=0; i<nRead; i++) {
			int v = bytes[i] & 0xff;
			hexChars[i*2] = hexArray[ v >>> 4 ];
			hexChars[i*2 + 1] = hexArray[ v & 0x0f ];
		}

		for (int i=0; i<hexChars.length; i=i+2) {
			if (i+1 < hexChars.length) {
				System.out.print(Character.toString(hexChars[i]) + Character.toString(hexChars[i+1]) + " ");
			} else {
				System.out.println((char)hexChars[i]);
			}

			if (i % 20 == 18)
				System.out.println();
		}
	}

	static String getTime() {
		SimpleDateFormat f = new SimpleDateFormat("[hh:mm:ss]");
		return f.format(new Date());
	}

	private static byte[] makeRecord(HandshakeType type) throws NoSuchAlgorithmException {
		System.out.println("[FUNC] makeRecord");
		ByteBuffer record = null;
		byte[] content = null;
		boolean prepared = false;

		switch (type)
		{
			case server_hello:
				content = makeServerHello();
				System.out.println("ServerHello: " + content.length);
				prepared = true;
				break;
			case certificate:
				content = makeServerCertificate();
				System.out.println("ServerCertificate: " + content.length);
				prepared = true;
				break;
			case server_hello_done:
				content = makeServerHelloDone();
				System.out.println("ServerHelloDone");
				prepared = true;
				break;
		}

		if (prepared) {
			int length;

			if (content == null)
				length = 0;
			else
				length = content.length;

			record = ByteBuffer.allocate(9 + length);
			record.put((byte) (ContentType.handshake.getMagicNumber()));
			record.put((byte) 0x03);
			record.put((byte) 0x03);
			record.putShort((short) (length + 4));

			switch (type) {
				case server_hello:
					record.put((byte) (HandshakeType.server_hello.getMagicNumber()));
					break;
				case certificate:
					record.put((byte) (HandshakeType.certificate.getMagicNumber()));
					break;
				case server_hello_done:
					record.put((byte) (HandshakeType.server_hello_done.getMagicNumber()));
					break;
			}

			record.put(lengthToBytes(length));
			if (content != null)
				record.put(content);
		}

		if (prepared)
			md.update(record.array());

		return record.array();
	}

	private static byte[] lengthToBytes(int length) {
		byte[] ret = new byte[3];
		ret[0] = (byte) ((length & 0x00ff0000) >> 16);
		ret[1] = (byte) ((length & 0x0000ff00) >> 8);
		ret[2] = (byte) (length & 0x000000ff);

		return ret;
	}

	private static void parseRecord(byte[] record) throws NoSuchAlgorithmException {
		System.out.println("[FUNC] parseRecord");
		byte contentType = record[0];
		if (contentType == 0x16)
			System.out.println("Message: Handshake");

		if (record[1] == 0x03 && record[2] == 0x03)
			System.out.println("Version: TLS 1.2");

		int length;
		length = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
		System.out.println("Length: " + length);

		byte[] content = new byte[length];
		System.arraycopy(record, 5, content, 0, length);

		if (contentType == 0x16)
			parseHandshake(content);
	}

	private static void parseHandshake(byte[] content) throws NoSuchAlgorithmException {
		System.out.println("[FUNC] parseHandshake");
		byte handshakeType = content[0];
		int length = ((content[1] & 0xFF) << 16) | ((content[2] & 0xFF) << 8) | (content[3] & 0xFF);
		System.out.println("Length: " + length);
		byte[] body = new byte[length];
		System.arraycopy(content, 4, body, 0, length);

		if (handshakeType == 0x1) {
			System.out.println("Handshake Type: Client Hello");
			parseClientHello(body);
		}
	}

	private static void parseClientHello(byte[] clientHello) throws NoSuchAlgorithmException {
		int offset = 0;
		int version = ((clientHello[offset] & 0xFF) << 8) | (clientHello[offset+1] & 0xFF);
		offset += 2;
		switch (version) {
		case 0x0301:
			System.out.println("Client Version: TLS 1.0");
			break;
		case 0x0302:
			System.out.println("Client Version: TLS 1.1");
			break;
		case 0x0303:
			System.out.println("Client Version: TLS 1.2");
			break;
		default:
			System.out.println("Client Version: No Support Version");
			System.exit(-1);
		}

		byte[] random = new byte[RANDOM_SIZE];
		System.arraycopy(clientHello, offset, random, 0, RANDOM_SIZE);
		int time = ((random[0] & 0xFF) << 24) | ((random[1] & 0xFF) << 16) | ((random[2] & 0xFF) << 8) | (random[3] & 0xFF);
		System.out.println("Client Unix Time: " + time);
		sp.setClientRandom(random);
		offset += RANDOM_SIZE;

		int sessionIDLength = clientHello[offset] & 0xff;
		offset += 1;
		System.out.println("Session ID Length: " + sessionIDLength);

		int bytesOfCiphers = ((clientHello[offset] & 0xff) << 8) | (clientHello[offset+1] & 0xff);
		offset += 2;
		System.out.println("# Of Ciphersuites: " + (bytesOfCiphers / 2));

		int cipher;
		for (int i=0; i<bytesOfCiphers; i+=2) {
			cipher = ((clientHello[offset+i] & 0xff) << 8) | (clientHello[offset+i+1] & 0xff);
			if (cipher == 0x003D) {
				System.out.println("TLS_RSA_WITH_AES_256_CBC_SHA256");
				sp.getCipherSuite().setCiphersuite((short)cipher);
				md = MessageDigest.getInstance("SHA-256");
				md.update(clientHello);
			}
		}

		offset += bytesOfCiphers;

		int bytesOfCompression = clientHello[offset] & 0xff;
		offset += 1;
		System.out.println("Bytes of Compression: " + bytesOfCompression);

		for (int i=0; i<bytesOfCompression; i++) {
			System.out.printf("%02X\n", clientHello[offset+i]);
		}
		offset += bytesOfCompression;
	}

	private static byte[] makeServerHello() throws NoSuchAlgorithmException {
		ServerHello serverHello = new ServerHello();
		serverHello.getVersion().setMajor((byte)0x03);
		serverHello.getVersion().setMinor((byte)0x03);
		serverHello.getCipherSuite().setCiphersuite(sp.getCipherSuite().getCiphersuite());

		return serverHello.getBytes();
	}

	private static byte[] makeServerCertificate() {
		Certificate cert = new Certificate();
		cert.setCertificate(certFile);

		return cert.getBytes();
	}

	private static byte[] makeServerHelloDone() {
		return null;
	}
}
