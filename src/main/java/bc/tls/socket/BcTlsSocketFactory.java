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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocketFactory;

import bc.tls.BcSecurityPrototype;
import bc.tls.CipherSuite;
import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;
import bc.tls.logging.LogLevel;

/**
 * BC tls socket factory, allows for per-connection authentication
 * 
 * @author super-horst
 *
 */
public class BcTlsSocketFactory extends SSLSocketFactory implements SocketFactoryManager {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("SocketFactory");

	/**
	 * Thread safe map to hold configuration TODO why thread safe?
	 */
	private volatile Map<String, Object> config = new ConcurrentHashMap<String, Object>();

	@Deprecated
	private String[] defaultCipherSuites;

	@Deprecated
	private String[] supportedCipherSuites;

	private boolean clientMode = true;

	private BcSecurityPrototype defaultPrototype;

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
		LOG.debug("Setting myself as default SSLSocketFactory");
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

	public BcTlsSocketFactory() {
		reset();
	}

	public BcTlsSocketFactory(BcSecurityPrototype prototype) {
		setDefaultSecurityPrototype(prototype);

		reset();
	}

	/**
	 * Reset to default configuration.
	 */
	protected void reset() {
		// TODO is this a reasonable selection?
		setSupportedCipherSuites(CipherSuite.DEFAULT);

		setDefaultTimeout(DEFAULT_TIMEOUT, TimeUnit.SECONDS);

		setConfigProperty(KEY_SOCKET_AUTO_CLOSE, Boolean.TRUE);
	}

	@Override
	public void setConfigProperty(final String key, final Object value) {
		LOG.trace(String.format("Setting config: %s - %s", key, value));
		this.config.put(key, value);
	}

	@Override
	public Object getConfigProperty(final String key) {
		return this.config.get(key);
	}

	@Override
	public BcSecurityPrototype getDefaultSecurityPrototype() {
		return this.defaultPrototype;
	}

	@Override
	public void setDefaultSecurityPrototype(BcSecurityPrototype prototype) {
		this.defaultPrototype = prototype;
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
	@Deprecated
	@Override
	public void setDefaultCipherSuites(String[] suites) {
		this.defaultCipherSuites = suites.clone();
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.defaultCipherSuites;
	}

	@Deprecated
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

	public BcTlsSocket createSocket(InetAddress host, int port, BcSecurityPrototype prototype) throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), null, prototype);
	}

	public BcTlsSocket createSocket(InetAddress host, int port, InetAddress localAddress, int localPort,
			BcSecurityPrototype prototype) throws IOException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localAddress, localPort),
				prototype);
	}

	public BcTlsSocket createSocket(String host, int port, InetAddress localHost, int localPort,
			BcSecurityPrototype prototype) throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), new InetSocketAddress(localHost, localPort),
				prototype);
	}

	public BcTlsSocket createSocket(String host, int port, BcSecurityPrototype prototype)
			throws IOException, UnknownHostException {
		return createSocket(null, new InetSocketAddress(host, port), null, prototype);
	}

	private BcTlsSocket createSocket(final Socket socket, final InetSocketAddress remoteAddress,
			final InetSocketAddress localAddress, BcSecurityPrototype prototype) throws IOException {

		return createSocket(socket, remoteAddress, localAddress, (Boolean) getConfigProperty(KEY_SOCKET_AUTO_CLOSE),
				prototype);
	}

	public BcTlsSocket createSocket(Socket s, String host, int port, boolean autoClose, BcSecurityPrototype prototype)
			throws IOException {
		return createSocket(s, new InetSocketAddress(host, port), null, autoClose, prototype);
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
	 * @param prototype
	 *            security override, defaults to {@code this.defaultPrototype}
	 * @return
	 * @throws IOException
	 */
	private BcTlsSocket createSocket(Socket rawSocket, final InetSocketAddress remoteAddress,
			final InetSocketAddress localAddress, boolean autoClose, BcSecurityPrototype prototype) throws IOException {
		// TODO hand out prototype clones
		BcSecurityPrototype securityPrototype = prototype == null ? this.defaultPrototype : prototype;

		if (rawSocket == null) {
			rawSocket = createRawSocket(remoteAddress, localAddress);
		}

		if (!rawSocket.isBound()) {
			rawSocket.bind(localAddress);
		}

		if (!rawSocket.isConnected()) {
			rawSocket.connect(remoteAddress, this.defaultTimeout.intValue());
		}

		if (LOG.isLevelEnabled(LogLevel.DEBUG)) {
			LOG.debug(String.format("Handing out socket: %s", rawSocket.toString()));
		}

		BcTlsSocket tlsSocket = new BcTlsSocket(rawSocket, autoClose, securityPrototype);
		tlsSocket.setUseClientMode(this.clientMode);

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

		Provider provider = null;
		if (prov instanceof String) {
			provider = Security.getProvider((String) prov);
		} else if (prov instanceof Provider) {
			provider = (Provider) prov;
		}

		if (provider == null) {
			return SecureRandom.getInstance(algorithm);
		}

		return SecureRandom.getInstance(algorithm, provider);
	}

	private Socket createRawSocket(final InetSocketAddress remoteAddress, final InetSocketAddress localAddress)
			throws IOException {
		Socket s = null;
		URI uri = URI.create(String.format("socket://" + remoteAddress.getHostName() + ":%d", remoteAddress.getPort()));
		ProxySelector ps = ProxySelector.getDefault();
		List<Proxy> proxyList = ps.select(uri);
		if (LOG.isLevelEnabled(LogLevel.TRACE)) {
			LOG.trace(String.format("Selector handed out %d proxies", proxyList.size()));
		}

		Iterator<Proxy> proxies = proxyList.iterator();
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

				LOG.error("Exception connecting to address", ioe);
			}
		}
		return s;
	}

}
