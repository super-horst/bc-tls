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
import java.net.Socket;
import java.security.SecureRandom;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

import org.bouncycastle.crypto.tls.TlsAuthentication;

import bc.tls.BcSecurityPrototype;
import bc.tls.logging.LogConsumer;
import bc.tls.logging.LogConsumerFactory;
import bc.tls.logging.LogLevel;

public class BcTlsServerSocket extends SSLServerSocket {

	private static final LogConsumer LOG = LogConsumerFactory.getTaggedConsumer("ServerSocket");

	private final BcSecurityPrototype securityPrototype;

	private ClientAuthMode clientAuthMode;
	private String[] supportedCipherSuites = new String[0];
	private String[] enabledCipherSuites = new String[0];
	private String[] supportedProtocols = new String[0];
	private String[] enabledProtocols = new String[0];
	private boolean enableSessionCreation;

	public BcTlsServerSocket(int port, BcSecurityPrototype prototype) throws IOException {
		super(port);
		this.securityPrototype = prototype;
	}

	public BcTlsServerSocket(int port, int backlog, BcSecurityPrototype prototype) throws IOException {
		super(port, backlog);
		this.securityPrototype = prototype;
	}

	public BcTlsServerSocket(int port, int backlog, InetAddress address, BcSecurityPrototype prototype)
			throws IOException {
		super(port, backlog, address);
		this.securityPrototype = prototype;
	}

	@Override
	public Socket accept() throws IOException {
		Socket rawSocket = super.accept();
		if (LOG.isLevelEnabled(LogLevel.DEBUG)) {
			LOG.debug(String.format("Received connection: %s", rawSocket.toString()));
		}

		// TODO hand out prototype clones
		BcTlsSocket tlsSocket = new BcTlsSocket(rawSocket, true, this.securityPrototype);
		tlsSocket.setEnabledCipherSuites(enabledCipherSuites);
		tlsSocket.startHandshake();
		return tlsSocket;
	}

	public void setSupportedCipherSuites(String[] suites) {
		this.supportedCipherSuites = suites.clone();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return supportedCipherSuites.clone();
	}

	@Override
	public String[] getEnabledCipherSuites() {
		return enabledCipherSuites.clone();
	}

	@Override
	public void setEnabledCipherSuites(String[] suites) {
		this.enabledCipherSuites = suites.clone();
	}

	public void setSupportedProtocols(String[] protocols) {
		this.supportedProtocols = protocols.clone();
	}

	@Override
	public String[] getSupportedProtocols() {
		return this.supportedProtocols;
	}

	@Override
	public String[] getEnabledProtocols() {
		return this.enabledProtocols.clone();
	}

	@Override
	public void setEnabledProtocols(String[] protocols) {
		this.enabledProtocols = protocols.clone();
	}

	@Override
	public void setNeedClientAuth(boolean need) {
		if (need) {
			this.clientAuthMode = ClientAuthMode.NEEDS;
		} else {
			this.clientAuthMode = ClientAuthMode.NONE;
		}
	}

	@Override
	public boolean getNeedClientAuth() {
		return this.clientAuthMode == ClientAuthMode.NEEDS;
	}

	@Override
	public void setWantClientAuth(boolean want) {
		if (want) {
			this.clientAuthMode = ClientAuthMode.WANTS;
		} else {
			this.clientAuthMode = ClientAuthMode.NONE;
		}
	}

	@Override
	public boolean getWantClientAuth() {
		return this.clientAuthMode == ClientAuthMode.WANTS;
	}

	@Override
	public void setUseClientMode(boolean mode) {
		if (mode == true) {
			throw new UnsupportedOperationException("Client functionality is not implemented here");
		}
	}

	@Override
	public boolean getUseClientMode() {
		return false;
	}

	@Override
	public void setEnableSessionCreation(boolean flag) {
		this.enableSessionCreation = flag;
	}

	@Override
	public boolean getEnableSessionCreation() {
		return this.enableSessionCreation;
	}
}
