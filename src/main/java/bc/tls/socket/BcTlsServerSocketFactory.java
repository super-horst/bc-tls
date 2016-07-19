package bc.tls.socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLServerSocketFactory;

public class BcTlsServerSocketFactory extends SSLServerSocketFactory implements SocketFactoryManager {


	@Override
	public void setConfigProperty(String key, Object value) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Object getConfigProperty(String key) {
		// TODO Auto-generated method stub
		return null;
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
	public ServerSocket createServerSocket(int port) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException {
		// TODO Auto-generated method stub
		return null;
	}

}
