package bc.tls.socket;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class BcTlsSocketFactoryTest {

	private static final Integer TEST_PORT = 12345;

	ServerSocket serverSocket;

	private BcTlsSocketFactory createFactory() {
		return new BcTlsSocketFactory();
	}

	private void checkRawSocket(BcTlsSocket socket) {
		try {
			Field f = socket.getClass().getDeclaredField("socket");
			f.setAccessible(true);
			Socket rawSocket = (Socket) f.get(socket);
			Assert.assertFalse(rawSocket instanceof BcTlsSocket);
			Assert.assertTrue(rawSocket.isBound());
			Assert.assertTrue(rawSocket.isConnected());
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@Before
	public void prepare() throws IOException {
		this.serverSocket = new ServerSocket(TEST_PORT);
	}

	@After
	public void cleanup() throws IOException {
		this.serverSocket.close();
	}

	@Test
	public void defaultRegistrationTest() {
		BcTlsSocketFactory.setDefault();
		SocketFactory sockFac = BcTlsSocketFactory.getDefault();
		Assert.assertTrue(sockFac instanceof BcTlsSocketFactory);
		Assert.assertSame(sockFac, BcTlsSocketFactory.getDefault());
	}

	@Test
	public void defaultCipherSuitsTest() {
		BcTlsSocketFactory sockFac = new BcTlsSocketFactory();
		String[] cipherSuites = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_SHA" };

		sockFac.setConfigProperty(BcTlsSocketFactory.KEY_DEFAULT_CIPHER_SUITES, cipherSuites);
		String[] factoryCiphers = sockFac.getDefaultCipherSuites();

		Assert.assertArrayEquals(cipherSuites, factoryCiphers);
	}

	@Test
	public void supportedCipherSuitsTest() {
		BcTlsSocketFactory sockFac = new BcTlsSocketFactory();
		String[] cipherSuites = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_SHA" };

		sockFac.setConfigProperty(BcTlsSocketFactory.KEY_SUPPORTED_CIPHER_SUITES, cipherSuites);
		String[] factoryCiphers = sockFac.getSupportedCipherSuites();

		Assert.assertArrayEquals(cipherSuites, factoryCiphers);
	}

	@Test
	public void simpleSocketCreationTest() throws UnknownHostException, IOException {
		SocketFactory sockFac = createFactory();

		try (Socket socket = sockFac.createSocket("localhost", TEST_PORT)) {
			Assert.assertTrue(socket instanceof BcTlsSocket);
			checkRawSocket((BcTlsSocket) socket);
		}
	}

	@Test
	public void locallyBoundSocketCreationTest() throws UnknownHostException, IOException {
		SocketFactory sockFac = createFactory();
		InetAddress addr = InetAddress.getByName("127.0.0.1");

		try (Socket socket = sockFac.createSocket("localhost", TEST_PORT, addr, 0)) {
			Assert.assertTrue(socket instanceof BcTlsSocket);
			checkRawSocket((BcTlsSocket) socket);
		}
	}

}
