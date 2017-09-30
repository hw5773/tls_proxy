import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.text.SimpleDateFormat;

public class ServerTest {
	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private final static int RANDOM_SIZE = 32;
	private final static int CHANGE_CIPHER_SPEC_LENGTH = 6;
	private final static int MASTER_SECRET_LENGTH = 48;
	private static byte major = 0x03;
	private static byte minor = 0x03;
	private static SecurityParameters sp;
	private static MessageDigest md;
	private static boolean ccsFlag = false;
	private static String certFile = "D:\\IntelliJ\\tls_proxy\\src\\carol_cert.crt";
	private static String keyFile = "D:\\IntelliJ\\tls_proxy\\src\\carol_priv.key";
	private static String caFile = "D:\\IntelliJ\\tls_proxy\\src\\ca_carol.pem";

	public static void main(String[] args) throws IOException {
		sp = new SecurityParameters();
		ServerSocket serverSocket = null;
		int port = 443;

		try {
			serverSocket = new ServerSocket(port);
			System.out.println(getTime() + " 서버가 준비되었습니다.");

			Socket socket = serverSocket.accept();
			InetAddress clientAddress = socket.getInetAddress();
			System.out.println(getTime() + clientAddress + " 에서 클라이언트가 접속했습니다.");

			OutputStream os = socket.getOutputStream();
			InputStream is = socket.getInputStream();

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
				os.write(certificate);
                byte[] serverHelloDone = makeRecord(HandshakeType.server_hello_done);
				os.write(serverHelloDone);

				nRead = is.read(data);
				System.out.println("nRead: " + nRead);

				if (nRead <0)
					break;
				byte[] clientKeyExchange = toBytes(data, nRead);
				parseRecord(clientKeyExchange);

				nRead = is.read(data);
				System.out.println("nRead: " + nRead);

				if (nRead < 0)
					break;
				byte[] changeCipherSpec = toBytes(data, CHANGE_CIPHER_SPEC_LENGTH);
				parseRecord(changeCipherSpec);
				byte[] clientFinished = new byte[nRead - CHANGE_CIPHER_SPEC_LENGTH];
				System.arraycopy(data, CHANGE_CIPHER_SPEC_LENGTH, clientFinished, 0, nRead - CHANGE_CIPHER_SPEC_LENGTH);
				parseRecord(clientFinished);

				while(true) {}
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

			if (i % 16 == 14)
				System.out.println();
		}
	}

	static String getTime() {
		SimpleDateFormat f = new SimpleDateFormat("[hh:mm:ss]");
		return f.format(new Date());
	}

	private static byte[] makeRecord(HandshakeType type) throws NoSuchAlgorithmException, IOException {
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
				System.out.println("ServerHelloDone: " + content.length);
				prepared = true;
				break;
		}

		if (prepared) {
			int length = content.length;

			record = ByteBuffer.allocate(5 + length);
			record.put((byte) (ContentType.handshake.getMagicNumber()));
			record.put(major);
			record.put(minor);
			record.putShort((short)length);
			record.put(content);
		}

		if (prepared)
			md.update(content);

		return record.array();
	}

	private static byte[] lengthToBytes(int length) {
		byte[] ret = new byte[3];
		ret[0] = (byte) ((length & 0x00ff0000) >> 16);
		ret[1] = (byte) ((length & 0x0000ff00) >> 8);
		ret[2] = (byte) (length & 0x000000ff);

		return ret;
	}

	private static void parseRecord(byte[] record) throws NoSuchAlgorithmException, IOException {
		System.out.println("[FUNC] parseRecord");
		byte contentType = record[0];
		if (contentType == ContentType.handshake.getMagicNumber())
			System.out.println("Message: Handshake");
		else if (contentType == ContentType.change_cipher_spec.getMagicNumber())
			System.out.println("Message: Change Cipher Spec");

		if (record[1] == 0x03 && record[2] == 0x03)
			System.out.println("Version: TLS 1.2");

		int length;
		length = ((record[3] & 0xFF) << 8) | (record[4] & 0xFF);
		System.out.println("Length: " + length);

		byte[] content = new byte[length];
		System.arraycopy(record, 5, content, 0, length);

		if (ccsFlag == true)
			content = decryptMessage(content);

		if (contentType == ContentType.handshake.getMagicNumber()) {
			System.out.println("Content Type: Handshake");
			parseHandshake(content);
		} else if (contentType == ContentType.change_cipher_spec.getMagicNumber()) {
			System.out.println("Content Type: Change Cipher Spec");
			parseChangeCipherSpec(content);
		}

		md.update(content);
	}

	// TODO: Need to implement this.
	private static byte[] decryptMessage(byte[] content) {
		byte[] key;
		return null;
	}

	private static void parseHandshake(byte[] content) throws NoSuchAlgorithmException, IOException {
		System.out.println("[FUNC] parseHandshake");
		byte handshakeType = content[0];
		int length = ((content[1] & 0xFF) << 16) | ((content[2] & 0xFF) << 8) | (content[3] & 0xFF);
		System.out.println("Length: " + length);
		byte[] body = new byte[length];
		System.arraycopy(content, 4, body, 0, length);

		if (handshakeType == HandshakeType.client_hello.getMagicNumber()) {
			System.out.println("Handshake Type: Client Hello");
			parseClientHello(body);
		} else if (handshakeType == HandshakeType.client_key_exchange.getMagicNumber()) {
			System.out.println("Handshake Type: Client Key Exchange");
			parseClientKeyExchange(body);
		} else if (handshakeType == HandshakeType.finished.getMagicNumber()) {
			System.out.println("Handshake Type: Client Finished");
			parseClientFinished(body);
		}
	}

	private static void checkVersion(int version) {
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
	}

	private static void parseChangeCipherSpec(byte[] ccs) {
		System.out.println("[FUNC] parseChangeCipherSpec");
		int offset = 0;
		byte data = ccs[offset];
		System.out.println("CCS: " + data);
		ccsFlag = true;
	}

	private static void parseClientHello(byte[] clientHello) throws NoSuchAlgorithmException {
		int offset = 0;
		int version = ((clientHello[offset] & 0xFF) << 8) | (clientHello[offset+1] & 0xFF);
		offset += 2;
		checkVersion(version);

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
			if (cipher == 0x003C) {
				System.out.println("TLS_RSA_WITH_AES_128_CBC_SHA256");
				sp.getCipherSuite().setCiphersuite((short)cipher);
				sp.setBulkCipiherAlgorithm(BulkCipiherAlgorithm.aes128);
				sp.setMacAlgorithm(MACAlgorithm.sha256);
				md = MessageDigest.getInstance("SHA-256");
				md.update(clientHello);
			} else if (cipher == 0x003D) {
				System.out.println("TLS_RSA_WITH_AES_256_CBC_SHA256");
				sp.getCipherSuite().setCiphersuite((short)cipher);
				sp.setBulkCipiherAlgorithm(BulkCipiherAlgorithm.aes256);
				sp.setMacAlgorithm(MACAlgorithm.sha256);
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

	private static void parseClientKeyExchange(byte[] cke) throws NoSuchAlgorithmException, IOException {
		System.out.println("[FUNC] parseClientKeyExchange");
		System.out.println("Length of Client Key Exchange: " + cke.length);
		int len = ((cke[0] & 0xff) << 8) | (cke[1] & 0xff);
		System.out.println("Length of Encrypted Premaster Secret: " + len);
		byte[] encryptedPremasterSecret = new byte[len];
		System.arraycopy(cke, 2, encryptedPremasterSecret, 0, len);

		byte[] ret = {0};
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(keyFile)));
			StringBuilder builder = new StringBuilder();
			boolean inKey = false;

			for (String line = br.readLine(); line != null; line = br.readLine()) {
				if (!inKey) {
					if (line.startsWith("-----BEGIN") && line.endsWith(" PRIVATE KEY-----")) {
						inKey = true;
					}
					continue;
				} else {
					if (line.startsWith("-----END") && line.endsWith(" PRIVATE KEY-----")) {
						inKey = false;
						break;
					}
					builder.append(line);
				}
			}
			byte[] privKeyBytes = DatatypeConverter.parseBase64Binary(builder.toString());
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privKey = keyFactory.generatePrivate(ks);
			System.out.println("Algorithm: " + privKey.getAlgorithm());
			Cipher decrypt = Cipher.getInstance("RSA");
			decrypt.init(Cipher.DECRYPT_MODE, privKey);
			ret = decrypt.doFinal(encryptedPremasterSecret);
		} catch (InvalidKeySpecException e) {
			System.out.println("Invalid Key Spec Exception");
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}

		System.out.println("----- PreMaster Secret -----");
		bytesToHex(ret, ret.length);
		sp.setMasterSecret(generateMasterSecret(ret));

		System.out.println("----- Client Nonce -----");
		bytesToHex(sp.getClientRandom(), sp.getClientRandom().length);

		System.out.println("----- Server Nonce -----");
		bytesToHex(sp.getServerRandom(), sp.getServerRandom().length);

		System.out.println("----- Master Secret -----");
		bytesToHex(sp.getMasterSecret(),sp.getMasterSecret().length);


	}

	private static void parseClientFinished(byte[] finished) {
		System.out.println("[FUNC] parseClientFinished");
	}

	private static byte[] makeServerHello() throws NoSuchAlgorithmException, IOException {
		ServerHello serverHello = new ServerHello();
		serverHello.getVersion().setMajor((byte)major);
		serverHello.getVersion().setMinor((byte)minor);
		serverHello.getCipherSuite().setCiphersuite(sp.getCipherSuite().getCiphersuite());
		sp.setServerRandom(serverHello.getRandom().getRandom());
		return serverHello.getBytes();
	}

	private static byte[] makeServerCertificate() {
		Certificate cert = new Certificate();
		cert.setCertificate(certFile);

		return cert.getBytes();
	}

	private static byte[] makeServerHelloDone() {
		int length = 4;
		ByteBuffer ret = ByteBuffer.allocate(length);
		ret.put((byte)HandshakeType.server_hello_done.getMagicNumber());
		ret.put(CommonFunc.lengthToBytes(0));
		return ret.array();
	}

	private static byte[] generateMasterSecret(byte[] pms) throws IOException {
		System.out.println("[FUNC] generateMasterSecret");
		ByteArrayOutputStream random = new ByteArrayOutputStream();
		random.write(sp.getClientRandom());
		random.write(sp.getServerRandom());
		return prf(pms, "master secret", random.toByteArray());
	}

	private static byte[] prf(byte[] secret, String label, byte[] seed) throws IOException {
		System.out.println("[FUNC] prf");
		int bytes = 0;

		if (label.equalsIgnoreCase("master secret")) {
			bytes = MASTER_SECRET_LENGTH;
		} else if (label.equalsIgnoreCase("key expansion")) {
			bytes = 2 * sp.getEncKeyLength() + 2 * sp.getMacKeyLength() + 2 * sp.getFixedIVLength();
		}

		System.out.println("Bytes is set to " + bytes);

		ByteArrayOutputStream s = new ByteArrayOutputStream();
		s.write(label.getBytes());
		s.write(seed);
		return pHash(secret, s.toByteArray(), bytes);
	}

	private static byte[] pHash(byte[] secret, byte[] seed, int bytes) throws IOException {
		System.out.println("[Func] pHash");
		ByteArrayOutputStream r = new ByteArrayOutputStream();
		byte[] ret = new byte[bytes];
		int num = bytes/(sp.getMacLength());
		if ((bytes % sp.getMacLength()) > 0)
			num += 1;

		int n = 0;
		byte[] a = seed;

		for (int i=0; i<num; i++) {
			ByteArrayOutputStream s = new ByteArrayOutputStream();
			a = hmacHash(secret, a);
			s.write(a);
			s.write(seed);
			r.write(hmacHash(secret, s.toByteArray()));
		}

		System.arraycopy(r.toByteArray(), 0, ret, 0, bytes);

		return ret;
	}

	private static byte[] hmacHash(byte[] secret, byte[] value) {
		System.out.println("[Func] hmacHash");
		try {
			SecretKeySpec ks;
			switch (sp.getMacAlgorithm()) {
				case md5:
					Mac hmacMD5 = Mac.getInstance("HmacMD5");
					ks = new SecretKeySpec(secret, "HmacMD5");
					hmacMD5.init(ks);
					return hmacMD5.doFinal(value);
				case sha1:
					Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
					ks = new SecretKeySpec(secret, "HmacSHA1");
					hmacSHA1.init(ks);
					return hmacSHA1.doFinal(value);
				case sha256:
					Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
					ks = new SecretKeySpec(secret, "HmacSHA256");
					hmacSHA256.init(ks);
					return hmacSHA256.doFinal(value);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return null;
	}
}
