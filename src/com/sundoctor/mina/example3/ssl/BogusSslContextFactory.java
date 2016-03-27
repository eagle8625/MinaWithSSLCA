package com.sundoctor.mina.example3.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BogusSslContextFactory {

	private static final Logger log = LoggerFactory.getLogger(BogusSslContextFactory.class);

	private static String serverKeys = "Le_AutoServer1.store";
	private static String serverKeysPassword = "123456";
	private static String serverTrust = "Le_AutoServer1.store";
	private static String serverTrustPassword = "123456";

	private static String clientKeys = "Le_AutoClient1.store";
	private static String clientKeysPassword = "123456";
	private static String clientTrust = "Le_AutoClient1.store";
	private static String clientTrustPassword = "123456";

	
	private static final String PROTOCOL = "TLS";
	private static final String KEY_MANAGER_FACTORY_ALGORITHM;	
	private static final String TRUST_MANAGER_FACTORY_ALGORITHM;

	static {
		String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
		if (algorithm == null) {
			algorithm = KeyManagerFactory.getDefaultAlgorithm();
		}
		KEY_MANAGER_FACTORY_ALGORITHM = algorithm;
		
		algorithm = Security.getProperty("ssl.TrustManagerFactory.algorithm");
		if (algorithm == null) {
			algorithm = TrustManagerFactory.getDefaultAlgorithm();
		}
		TRUST_MANAGER_FACTORY_ALGORITHM = algorithm;
	}

	private static SSLContext serverInstance = null;
	private static SSLContext clientInstance = null;

	/**
	 * Get SSLContext singleton.
	 * 
	 * @return SSLContext
	 * @throws java.security.GeneralSecurityException
	 * 
	 */
	public static SSLContext getInstance(boolean server) throws GeneralSecurityException, IOException {
		SSLContext retInstance = null;
		if (server) {
			synchronized (BogusSslContextFactory.class) {
				if (serverInstance == null) {
					try {
						serverInstance = createBougusServerSslContext();
					} catch (Exception ioe) {
						throw new GeneralSecurityException("Can't create Server SSLContext:" + ioe);
					}
				}
			}
			retInstance = serverInstance;
		} else {
			synchronized (BogusSslContextFactory.class) {
				if (clientInstance == null) {
					clientInstance = createBougusClientSslContext();
				}
			}
			retInstance = clientInstance;
		}
		return retInstance;
	}

	private static SSLContext createBougusServerSslContext() throws GeneralSecurityException, IOException {

		// Initialize the SSLContext to work with our key managers.
		SSLContext sslContext = SSLContext.getInstance(PROTOCOL);
		sslContext.init(getKeyManagers(serverKeys, serverKeysPassword,true),
				getTrustManagers(serverTrust,serverTrustPassword,true), null);

		return sslContext;
	}

	private static SSLContext createBougusClientSslContext() throws GeneralSecurityException, IOException {
		SSLContext context = SSLContext.getInstance(PROTOCOL);
		context.init(getKeyManagers(clientKeys, clientKeysPassword,false),
				getTrustManagers(clientTrust,clientTrustPassword,false), null);

		return context;
	}

	private static KeyManager[] getKeyManagers(String keysfile, String password, boolean server) throws GeneralSecurityException,
			IOException {
		// First, get the default KeyManagerFactory.
		KeyManagerFactory kmf = KeyManagerFactory.getInstance(KEY_MANAGER_FACTORY_ALGORITHM);
		
		// Next, set up the TrustStore to use. We need to load the file into
		// a KeyStore instance.
		KeyStore ks = null;
		if(server){
			 ks = KeyStore.getInstance("jks");
		 }else {
			 ks = KeyStore.getInstance("jks");
		}

		InputStream in = BogusSslContextFactory.class.getResourceAsStream(keysfile);
		ks.load(in, password.toCharArray());
		in.close();

		// Now we initialise the KeyManagerFactory with this KeyStore	
		kmf.init(ks, password.toCharArray());
		KeyManager[] dd = kmf.getKeyManagers();
		// And now get the TrustManagers
		return dd;
	}
	
	protected static TrustManager[] getTrustManagers(String trustfile,String pasword, boolean server) throws IOException, GeneralSecurityException {
		// First, get the default TrustManagerFactory.
		TrustManagerFactory tmFact = TrustManagerFactory.getInstance(TRUST_MANAGER_FACTORY_ALGORITHM);

		// Next, set up the TrustStore to use. We need to load the file into
		// a KeyStore instance.		
		InputStream in = BogusSslContextFactory.class.getResourceAsStream(trustfile);
		KeyStore ks;
		if(server){
			 ks = KeyStore.getInstance("jks");
		}else{
			 ks = KeyStore.getInstance("jks");
		}
		ks.load(in, pasword.toCharArray());
		in.close();

		// Now we initialise the TrustManagerFactory with this KeyStore
		tmFact.init(ks);

		// And now get the TrustManagers
		TrustManager[] tms = tmFact.getTrustManagers();
		return tms;
	}

}
