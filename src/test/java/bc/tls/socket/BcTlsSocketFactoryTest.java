package bc.tls.socket;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import bc.tls.CipherSuite;

public class BcTlsSocketFactoryTest {

	private static final Integer TEST_PORT = 12345;

	ServerSocket serverSocket;
	SSLParameters params;

	private void checkRawSocket(BcTlsSocket socket) {
		try {
			Field f = getField(socket.getClass(), "socket");
			f.setAccessible(true);
			Socket rawSocket = (Socket) f.get(socket);
			Assert.assertFalse(rawSocket instanceof BcTlsSocket);
			Assert.assertTrue(rawSocket.isBound());
			Assert.assertTrue(rawSocket.isConnected());
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	@SuppressWarnings("rawtypes")
	private static Field getField(Class clazz, String fieldName) throws NoSuchFieldException {
		try {
			return clazz.getDeclaredField(fieldName);
		} catch (NoSuchFieldException e) {
			Class superClass = clazz.getSuperclass();
			if (superClass == null) {
				throw e;
			} else {
				return getField(superClass, fieldName);
			}
		}
	}

	@Before
	public void prepare() throws IOException {
		this.serverSocket = new ServerSocket(TEST_PORT);
		this.params = new SSLParameters(CipherSuite.DEFAULT);
	}

	@After
	public void cleanup() throws IOException {
		this.serverSocket.close();
	}

	@Test
	public void defaultRegistrationTest() {
		BcTlsSocketFactory.setDefault();
		SocketFactory sockFac = SSLSocketFactory.getDefault();
		Assert.assertTrue(sockFac instanceof BcTlsSocketFactory);
		Assert.assertSame(sockFac, BcTlsSocketFactory.getDefault());
	}

	@Test
	public void defaultCipherSuitsTest() {
		BcTlsSocketFactory sockFac = new BcTlsSocketFactory(this.params);
		String[] cipherSuites = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_SHA" };

		sockFac.setDefaultCipherSuites(cipherSuites);
		String[] factoryCiphers = sockFac.getDefaultCipherSuites();

		Assert.assertArrayEquals(cipherSuites, factoryCiphers);
	}

	@Test
	public void supportedCipherSuitsTest() {
		BcTlsSocketFactory sockFac = new BcTlsSocketFactory(this.params);
		String[] cipherSuites = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_SHA" };

		sockFac.setSupportedCipherSuites(cipherSuites);
		String[] factoryCiphers = sockFac.getSupportedCipherSuites();

		Assert.assertArrayEquals(cipherSuites, factoryCiphers);
	}

	@Test
	public void simpleSocketCreationTest() throws UnknownHostException, IOException {
		SocketFactory sockFac =  new BcTlsSocketFactory(this.params);

		try (Socket socket = sockFac.createSocket("localhost", TEST_PORT)) {
			Assert.assertTrue(socket instanceof BcTlsSocket);
			checkRawSocket((BcTlsSocket) socket);
		}
	}

	@Test
	public void locallyBoundSocketCreationTest() throws UnknownHostException, IOException {
		SocketFactory sockFac =  new BcTlsSocketFactory(this.params);
		InetAddress addr = InetAddress.getByName("127.0.0.1");

		try (Socket socket = sockFac.createSocket("localhost", TEST_PORT, addr, 0)) {
			Assert.assertTrue(socket instanceof BcTlsSocket);
			checkRawSocket((BcTlsSocket) socket);
		}
	}

}
