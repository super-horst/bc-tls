package bc.tls.socket;

import java.io.IOException;
import java.net.InetAddress;

import javax.net.ssl.SSLServerSocket;

public class BcTlsServerSocket extends SSLServerSocket {

	private ClientAuthMode clientAuthMode;
	private String[] supportedCipherSuites;
	private String[] enabledCipherSuites;
	private String[] supportedProtocols;
	private String[] enabledProtocols;
	private boolean enableSessionCreation;

	public BcTlsServerSocket(int port) throws IOException {
		super(port);
		// TODO Auto-generated constructor stub
	}

	public BcTlsServerSocket(int port, int backlog) throws IOException {
		super(port, backlog);
		// TODO Auto-generated constructor stub
	}

	public BcTlsServerSocket(int port, int backlog, InetAddress address) throws IOException {
		super(port, backlog, address);
		// TODO Auto-generated constructor stub
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
