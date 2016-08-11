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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;

import bc.tls.CipherSuite;

/**
 * BC tls server socket factory
 * 
 * @author super-horst
 *
 */
public class BcTlsServerSocketFactory extends SSLServerSocketFactory implements SocketFactoryManager {

	/**
	 * Thread safe map to hold configuration TODO why thread safe?
	 */
	private volatile Map<String, Object> config = new ConcurrentHashMap<String, Object>();
	private Long defaultTimeout;
	private String[] defaultCipherSuites;
	private String[] supportedCipherSuites;

	private SSLParameters defaults;

	/**
	 * Default constructor
	 */
	public BcTlsServerSocketFactory(SSLParameters defaults) {
		this.defaults = defaults;
		setDefaultCipherSuites(defaults.getCipherSuites());

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
		config.put(key, value);
	}

	@Override
	public Object getConfigProperty(final String key) {
		return config.get(key);
	}

	@Override
	public Long getDefaultTimeout() {
		return defaultTimeout;
	}

	@Override
	public void setDefaultTimeout(Long timeout, TimeUnit unit) {
		this.defaultTimeout = unit.toMillis(timeout);
	}

	@Override
	public void setDefaultCipherSuites(String[] suites) {
		this.defaultCipherSuites = suites.clone();
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return this.defaultCipherSuites;
	}

	/**
	 * Set the supported cipher suites
	 * 
	 * @param suites
	 *            cipher suites to set
	 */
	@Override
	public void setSupportedCipherSuites(String[] suites) {
		this.supportedCipherSuites = suites.clone();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return this.supportedCipherSuites;
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port) throws IOException {
		return createSocket(port, null, null);
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port, int backlog) throws IOException {
		return createSocket(port, backlog, null);
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		return createSocket(port, backlog, ifAddress);
	}

	private BcTlsServerSocket createSocket(Integer port, Integer backlog, InetAddress ifAddress) throws IOException {
		return new BcTlsServerSocket(0, this.defaults);

		// TODO implement! :)

		// if (clientAuthMode == ClientAuthMode.NEEDS) {
		// tlsSocket.setNeedClientAuth(true);
		// } else {
		// tlsSocket.setWantClientAuth(clientAuthMode == ClientAuthMode.WANTS);
		// }

	}

}
