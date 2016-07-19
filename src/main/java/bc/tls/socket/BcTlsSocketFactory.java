/**
 * BouncyCastle TLS implementation
 * Copyright (C) 2016  super-horst
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as 
 * published by the Free Software Foundation; either version 3 of the 
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */
package bc.tls.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.crypto.tls.TlsAuthentication;
import bc.tls.CipherSuite;

/**
 * Configurable BC tls socket factory.
 * 
 * @author super-horst
 *
 */
public class BcTlsSocketFactory extends SSLSocketFactory implements SocketFactoryManager {

	/**
	 * Thread safe map to hold configuration
	 */
	private volatile Map<String, Object> config = new ConcurrentHashMap<String, Object>();

	/**
	 * Client authentication credentials
	 */
	private volatile Map<SocketAddress, CredentialContainer> credentials = new ConcurrentHashMap<SocketAddress, CredentialContainer>();

	/**
	 * Set {@link BcTlsSocketFactory} as default ssl socket provider.
	 * 
	 * @throws IllegalStateException
	 *             if the provider could not be set
	 */
	public static synchronized void setDefault() throws IllegalStateException {
		if (!setSecurityProperty("ssl.SocketFactory.provider",
				BcTlsSocketFactory.class.getCanonicalName())) {
			throw new IllegalStateException("Unable to set security property for socket factory");
		}
	}

	private static Boolean setSecurityProperty(final String name, final String value) {
		if (name == null || value == null) {
			throw new IllegalArgumentException(
					String.format("Neither name (%s) nor value (%s) may be null", name, value));
		}

		AccessController.doPrivileged(new PrivilegedAction<Void>() {
			public Void run() {
				java.security.Security.setProperty(name, value);
				return null;
			}
		});

		return AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
			public Boolean run() {
				return value == java.security.Security.getProperty(name);
			}
		});
	}

	/**
	 * Default constructor
	 */
	public BcTlsSocketFactory() {
		reset();
	}

	/**
	 * Reset to default configuration.
	 */
	protected void reset() {
		Long timeout = Long.valueOf(TimeUnit.SECONDS.toMillis(DEFAULT_TIMEOUT));
		setConfigProperty(KEY_TIMEOUT, timeout.intValue());

		setConfigProperty(KEY_DEFAULT_CIPHER_SUITES, CipherSuite.DEFAULT);
		setConfigProperty(KEY_SOCKET_AUTO_CLOSE, Boolean.TRUE);
		setConfigProperty(KEY_DEFAULT_AUTHENTICATION, new BcTlsAuthentication());
	}

	@Override
	public void setConfigProperty(final String key, final Object value) {
		config.put(key, value);
	}

	@Override
	public Object getConfigProperty(final String key) {
		return config.get(key);
	}

	/**
	 * @see #registerCredentials(InetSocketAddress, SecureRandom,
	 *      TlsAuthentication)
	 * 
	 * @param host
	 *            remote host
	 * @param port
	 *            remote port number
	 * @param random
	 *            random to use
	 * @param authentication
	 *            authentication to use
	 */
	public void registerCredentials(String host, int port, SecureRandom random, TlsAuthentication authentication) {
		registerCredentials(new InetSocketAddress(host, port), random, authentication);
	}

	/**
	 * Registers a {@link SecureRandom} and {@link TlsAuthentication} object for
	 * this address.
	 * <p>
	 * Allows for registration of unique security parameters for different
	 * remote hosts. This might be useful in a case where multiple tls client
	 * connections requiring separate authentication.
	 * 
	 * @param address
	 *            remote socket address
	 * @param random
	 *            random to use
	 * @param authentication
	 *            authentication to use
	 */
	public void registerCredentials(SocketAddress address, SecureRandom random, TlsAuthentication authentication) {
		credentials.put(address, new CredentialContainer(random, authentication));
	}

	@Override
	public String[] getDefaultCipherSuites() {
		Object property = getConfigProperty(KEY_DEFAULT_CIPHER_SUITES);
		if (property instanceof String[]) {
			return (String[]) property;
		}
		if (property instanceof CipherSuite[]) {
			return CipherSuite.convert((CipherSuite[]) property);
		}
		return new String[0];
	}

	@Override
	public String[] getSupportedCipherSuites() {
		Object property = getConfigProperty(KEY_SUPPORTED_CIPHER_SUITES);
		if (property instanceof String[]) {
			return (String[]) property;
		}
		if (property instanceof CipherSuite[]) {
			return CipherSuite.convert((CipherSuite[]) property);
		}
		return new String[0];
	}

	@Override
	public BcTlsSocket createSocket(InetAddress host, int port) throws IOException {
		return createSocket(host, port, null, 0);
	}

	@Override
	public BcTlsSocket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort)
			throws IOException {
		String hostname = host.getHostName();
		if (hostname != null) {
			Socket socket = createRawSocket(hostname, port, new InetSocketAddress(localAddress, localPort));
			return createSocket(socket, hostname, port);
		}

		hostname = host.getCanonicalHostName();
		if (hostname != null) {
			Socket socket = createRawSocket(hostname, port, new InetSocketAddress(localAddress, localPort));
			return createSocket(socket, hostname, port);
		}

		hostname = host.getHostAddress();
		if (hostname != null) {
			Socket socket = createRawSocket(hostname, port, new InetSocketAddress(localAddress, localPort));
			return createSocket(socket, hostname, port);
		}
		throw new IOException("Unable to resolve hostname " + host.toString());
	}

	@Override
	public BcTlsSocket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		Socket socket = createRawSocket(host, port, new InetSocketAddress(localHost, localPort));
		return createSocket(socket, host, port);
	}

	@Override
	public BcTlsSocket createSocket(String host, int port) throws IOException, UnknownHostException {
		return createSocket(null, host, port);
	}

	private BcTlsSocket createSocket(Socket socket, String host, int port) throws IOException {
		Boolean autoClose = (Boolean) getConfigProperty(KEY_SOCKET_AUTO_CLOSE);
		return createSocket(socket, host, port, autoClose.booleanValue());
	}

	@Override
	public BcTlsSocket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		if (s == null) {
			return buildSslSocket(createRawSocket(host, port, null), autoClose);
		}

		if (!s.isBound()) {
			s.bind(null);
		}

		if (!s.isConnected()) {
			s.connect(new InetSocketAddress(host, port), (Integer) getConfigProperty(KEY_TIMEOUT));
		}

		return buildSslSocket(s, autoClose);
	}

	private Socket createRawSocket(final String host, final int port, InetSocketAddress localAddress)
			throws IOException {
		Socket s = null;
		URI uri = URI.create(String.format("socket://" + host + ":%d", port));
		ProxySelector ps = ProxySelector.getDefault();
		Iterator<Proxy> proxies = ps.select(uri).iterator();

		while (proxies.hasNext()) {
			Proxy proxy = proxies.next();
			try {
				s = new Socket(proxy);
				s.bind(localAddress);
				s.connect(new InetSocketAddress(uri.getHost(), uri.getPort()),
						(Integer) getConfigProperty(KEY_TIMEOUT));
				break;
			} catch (IOException ioe) {
				if (s != null) {
					s.close();
				}

				if (proxy.equals(Proxy.NO_PROXY)) {
					throw ioe;
				}
				ps.connectFailed(uri, proxy.address(), ioe);

				if (!proxies.hasNext()) {
					throw new IOException("Unable to connect to " + uri, ioe);
				}
			}
		}
		return s;
	}

	private BcTlsSocket buildSslSocket(Socket rawSocket, boolean autoClose) {
		InetSocketAddress addr = new InetSocketAddress(rawSocket.getInetAddress(), rawSocket.getPort());
		CredentialContainer container = credentials.get(addr);

		SecureRandom random = null;
		TlsAuthentication auth = null;
		if (container != null) {
			random = container.random;
			auth = container.authentication;
		}

		if (random == null) {
			random = new SecureRandom();
		}
		if (auth == null) {
			auth = (TlsAuthentication) BcTlsSocketFactory.this.getConfigProperty(KEY_DEFAULT_AUTHENTICATION);
		}

		BcTlsSocket tlsSocket = new BcTlsSocket(rawSocket, autoClose, random, auth);

		tlsSocket.setUseClientMode(true);
		tlsSocket.setEnabledCipherSuites(getDefaultCipherSuites());
		tlsSocket.setSupportedCipherSuites(getSupportedCipherSuites());

		// TODO move to server socket factory
		// if (clientAuthMode == ClientAuthMode.NEEDS) {
		// tlsSocket.setNeedClientAuth(true);
		// } else {
		// tlsSocket.setWantClientAuth(clientAuthMode == ClientAuthMode.WANTS);
		// }

		return tlsSocket;
	}

	/**
	 * Struct to keep random and authentication object together
	 * 
	 * @author super-horst
	 *
	 */
	private final class CredentialContainer {

		private final SecureRandom random;
		private final TlsAuthentication authentication;

		public CredentialContainer(SecureRandom random, TlsAuthentication authentication) {
			this.random = random;
			this.authentication = authentication;
		}
	}

}
