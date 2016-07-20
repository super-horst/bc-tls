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
import java.net.ServerSocket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLServerSocketFactory;

import bc.tls.CipherSuite;

public class BcTlsServerSocketFactory extends SSLServerSocketFactory implements SocketFactoryManager {

	/**
	 * Thread safe map to hold configuration
	 */
	private volatile Map<String, Object> config = new ConcurrentHashMap<String, Object>();

	/**
	 * Default constructor
	 */
	public BcTlsServerSocketFactory() {
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

	@Override
	public String[] getDefaultCipherSuites() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String[] getSupportedCipherSuites() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port, int backlog) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public BcTlsServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	private BcTlsServerSocket createSocket() throws IOException {
		return new BcTlsServerSocket(0);

		// if (clientAuthMode == ClientAuthMode.NEEDS) {
		// tlsSocket.setNeedClientAuth(true);
		// } else {
		// tlsSocket.setWantClientAuth(clientAuthMode == ClientAuthMode.WANTS);
		// }

	}

}
