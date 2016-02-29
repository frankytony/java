package com.ericsson.dve.custom.authenticationplugin;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class LDAPSSLFactory extends SSLSocketFactory {
	private SSLSocketFactory factory;

	public LDAPSSLFactory() {
		try {

			SSLContext sslcontext = SSLContext.getInstance("TLS");

			TrustManager[] trustManager = new TrustManager[] { new X509TrustManager() {

				@Override
				public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
					return;
				}

				@Override
				public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
					
					return;
				}

				@Override
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}

			} };

			sslcontext.init(null, trustManager, new java.security.SecureRandom());

			factory = (SSLSocketFactory) sslcontext.getSocketFactory();

		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public static SSLSocketFactory getDefault() {

		return new LDAPSSLFactory();

	}

	@Override
	public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException {
		return factory.createSocket(arg0, arg1, arg2, arg3);
	}

	@Override
	public String[] getDefaultCipherSuites() {
		return factory.getDefaultCipherSuites();
	}

	@Override
	public String[] getSupportedCipherSuites() {
		return factory.getSupportedCipherSuites();
	}

	@Override
	public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
		return factory.createSocket(s, i);
	}

	@Override
	public Socket createSocket(InetAddress inaddr, int i) throws IOException {
		return factory.createSocket(inaddr, i);
	}

	@Override
	public Socket createSocket(String s, int i, InetAddress inaddr1, int j) throws IOException, UnknownHostException {
		return factory.createSocket(s, i, inaddr1, j);
	}

	@Override
	public Socket createSocket(InetAddress inaddr, int i, InetAddress inaddr1, int j) throws IOException {
		return factory.createSocket(inaddr, i, inaddr1, j);
	}

}
