package com.sundoctor.mina.example3.ssl.server;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.ssl.SslFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLSession;
import java.security.cert.X509Certificate;

public class TLSServerHandler extends IoHandlerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(TLSServerHandler.class);

	public void sessionCreated(IoSession session) throws Exception {
		System.out.println("[NIO Server]>> sessionCreated");
	}

	public void sessionOpened(IoSession session) throws Exception {
		System.out.println("[NIO Server]>> sessionOpened");
		session.write("welcome to ssl server");
	}

	public void sessionClosed(IoSession session) throws Exception {
		System.out.println("[NIO Server]>> sessionClosed");
	}

	public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
		System.out.println("[NIO Server]>> sessionIdle");
	}

	public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
		System.out.println("[NIO Server]>> exceptionCaught :");
		cause.printStackTrace();
	}

	public void messageReceived(IoSession session, Object message) throws Exception {
		logger.debug("[NIO Server]>> messageReceived");
		System.out.println("[NIO Server Received]>> : {}"+(String) message);

		String msg=message.toString();
		if( msg.trim().equalsIgnoreCase("") ) {
			Object obj=session.getAttribute(SslFilter.SSL_SESSION);
			String certid="";
			if(obj!=null &&obj instanceof SSLSession)
			{
				SSLSession ssl=(SSLSession)obj;
				X509Certificate cert=(X509Certificate) ssl.getPeerCertificates()[0];
				certid=cert.getSerialNumber().toString();
				System.out.println("Cert DN:"+cert.getSubjectDN().getName());
			}
		}
		session.write("you are in security channel");
	}

	public void messageSent(IoSession session, Object message) throws Exception {
		System.out.println("[NIO Server]>> messageSent");
		System.out.println("[NIO Server messageSent]>> : {}"+(String) message);
	}
}