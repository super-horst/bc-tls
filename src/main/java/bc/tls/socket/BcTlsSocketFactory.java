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
import java.net.URI;
import java.net.UnknownHostException;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.crypto.tls.TlsAuthentication;
import bc.tls.CipherSuite;

/**
 * BC tls socket factory, allows for per-connection authentication
 * 
 * @author super-horst
 *
 */
public class BcTlsSocketFactory extends SSLSocketFactory implements SocketFactoryManager {

	/**
	 * Thread safe map to hold configuration
	 * TODO why thread safe?
	 */
	private volatile Map<String, Object> config = new ConcurrentHashMap<String, Object>();

	private String[] defaultCipherSuites;

	private String[] supportedCipherSuites;

	private boolean clientMode = true;

	private TlsAuthentication defaultAuth;

	/**
	 * The default socket timeout in milliseconds
	 */
	private Long defaultTimeout;

	/**
	 * Set {@link BcTlsSocketFactory} as default ssl socket provider.
	 * 
	 * @throws IllegalStateException
	 *             if the provider could not be set
	 */
	public static synchronized void setDefault() throws IllegalStateException {
		if (!setSecurityProperty("ssl.SocketFactory.provider", BcTlsSocketFactory.class.getCanonicalName())) {
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
	public BcTlsSocketFactory(SSLParameters defaults) {
		setDefaultCipherSuites(defaults.getCipherSuites());

		reset();
	}

	/**
	 * Reset to default configuration.
	 */
	protected void reset() {
		// TODO is this a reasonable selection?
		setSupportedCipherSuites(CipherSuite.DEFAULT);
		
		setDefaultAuthentication(new BcTlsAuthentication());
		setDefaultTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS);

		setConfigProperty(KEY_SOCKET_AUTO_CLOSE, Boolean.TRUE);
	}

	@Override
	public void setConfigProperty(final String key, final Object value) {
		this.config.put(key, value);
	}

	@Override
	public Object getConfigProperty(final String key) {
		return this.config.get(key);
	}

	/**
	 * @return this factory's default authentication
	 */
	public TlsAuthentication getDefaultAuthentication() {
		return this.defaultAuth;
	}

	/**
	 * @param defaultAuth
	 *            this factory's new default authentication
	 */
	public void setDefaultAuthentication(TlsAuthentication defaultAuth) {
		this.defaultAuth = defaultAuth;
	}

	@Override
	public Long getDefaultTimeout() {
		return defaultTimeout;
	}

	@Override
	public void setDefaultTimeout(Long timeout, TimeUnit unit) {
		this.defaultTimeout = unit.toMillis(timeout);
	}

	/**
	 * Set the default cipher suites
	 * 
	 * @param suites
	 *            cipher suites to set
	 */
	@Override
	public void setDefaultCipherSuites(String[] suites) {
		this.defaultCipherSuites = suites.clone();
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.defaultCipherSuites;
	}

	@Override
	public void setSupportedCipherSuites(String[] suites) {
		this.supportedCipherSuites = suites.clone();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return this.supportedCipherSuites;
	}

	/**
	 * @return whether or not this factory produces client sockets
	 */
	public boolean isClientFactory() {
		return this.clientMode;
	}

	/**
	 * DEFAULTS to {@code true}
	 * 
	 * @param clientMode
	 *            if this factory is supposed to produce client sockets
	 */
	public void setClientFactory(boolean clientMode) {
		this.clientMode = clientMode;
	}

	@Override
	public BcTlsSocket createSocket(InetAddress host, int port) throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), null, null);
	}

	@Override
	public BcTlsSocket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort)
			throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localAddress, localPort),
				null);
	}

	@Override
	public BcTlsSocket createSocket(String host, int port, InetAddress localHost, int localPort)
			throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localHost, localPort), null);
	}

	@Override
	public BcTlsSocket createSocket(String host, int port) throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), null, null);
	}

	@Override
	public BcTlsSocket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
		return createSocket(s, new InetSocketAddress(host, port), null, autoClose, null);
	}

	public BcTlsSocket createSocket(InetAddress host, int port, TlsAuthentication auth) throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), null, auth);
	}

	public BcTlsSocket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort,
			TlsAuthentication auth) throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localAddress, localPort),
				auth);
	}

	public BcTlsSocket createSocket(String host, int port, InetAddress localHost, int localPort, TlsAuthentication auth)
			throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localHost, localPort), auth);
	}

	public BcTlsSocket createSocket(String host, int port, TlsAuthentication auth)
			throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), null, auth);
	}

	private BcTlsSocket createSocket(final Socket socket, final InetSocketAddress remoteAddress,
			final InetSocketAddress localAddress, TlsAuthentication auth) throws IOException {

		return createSocket(socket, remoteAddress, localAddress, (Boolean) getConfigProperty(KEY_SOCKET_AUTO_CLOSE),
				auth);
	}

	public BcTlsSocket createSocket(Socket s, String host, int port, boolean autoClose, TlsAuthentication auth)
			throws IOException {
		return createSocket(s, new InetSocketAddress(host, port), null, autoClose, auth);
	}

	/**
	 * Final factory method
	 * 
	 * @param socket
	 *            the raw socket, if already one exists
	 * @param remoteAddress
	 *            address to connect to
	 * @param localAddress
	 *            local address to bind to
	 * @param autoClose
	 *            auto close underlying socket, if tls socket closes
	 * @param auth
	 *            authentication override, defaults to {@code defaultAuth}
	 * @return
	 * @throws IOException
	 */
	private BcTlsSocket createSocket(Socket rawSocket, final InetSocketAddress remoteAddress,
			final InetSocketAddress localAddress, boolean autoClose, TlsAuthentication auth) throws IOException {

		TlsAuthentication authentication = auth == null ? this.defaultAuth : auth;

		if (rawSocket == null) {
			rawSocket = createRawSocket(remoteAddress, localAddress);
		}

		if (!rawSocket.isBound()) {
			rawSocket.bind(null);
		}

		if (!rawSocket.isConnected()) {
			rawSocket.connect(remoteAddress, this.defaultTimeout.intValue());
		}

		SecureRandom random;
		try {
			random = getRandom();
		} catch (NoSuchAlgorithmException e) {
			throw new IOException("Unable to select source of randomness", e);
		}

		BcTlsSocket tlsSocket = new BcTlsSocket(rawSocket, autoClose, random, authentication);

		tlsSocket.setUseClientMode(this.clientMode);
		tlsSocket.setEnabledCipherSuites(getDefaultCipherSuites());
		tlsSocket.setSupportedCipherSuites(getSupportedCipherSuites());

		return tlsSocket;

	}

	private SecureRandom getRandom() throws NoSuchAlgorithmException {
		Object algo = getConfigProperty(KEY_RANDOM_ALGORITHM);
		if (algo == null || !(algo instanceof String)) {
			return new SecureRandom();
		}
		String algorithm = (String) algo;

		Object prov = getConfigProperty(KEY_RANDOM_PROVIDER);
		if (prov == null) {
			return SecureRandom.getInstance(algorithm);
		}

		Provider provider;
		if (prov instanceof String) {
			provider = Security.getProvider((String) prov);
		} else if (prov instanceof Provider) {
			provider = (Provider) prov;
		} else {
			return SecureRandom.getInstance(algorithm);
		}

		return SecureRandom.getInstance(algorithm, provider);
	}

	private Socket createRawSocket(final InetSocketAddress remoteAddress, final InetSocketAddress localAddress)
			throws IOException {
		Socket s = null;
		URI uri = URI.create(String.format("socket://" + remoteAddress.getHostName() + ":%d", remoteAddress.getPort()));
		ProxySelector ps = ProxySelector.getDefault();
		Iterator<Proxy> proxies = ps.select(uri).iterator();

		while (proxies.hasNext()) {
			Proxy proxy = proxies.next();
			try {
				s = new Socket(proxy);
				s.bind(localAddress);
				s.connect(remoteAddress, this.defaultTimeout.intValue());
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
					throw new IOException("Unable to connect to through proxy" + uri, ioe);
				}
			}
		}
		return s;
	}

}
