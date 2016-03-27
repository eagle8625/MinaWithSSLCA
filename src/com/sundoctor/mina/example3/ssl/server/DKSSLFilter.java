package com.sundoctor.mina.example3.ssl.server;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.ssl.SslFilter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

/**
 * Created by Bin on 3/25/16.
 */
public class DKSSLFilter extends SslFilter {
    public DKSSLFilter(SSLContext sslContext) {
        super(sslContext,true);
    }

    @Override
    public void messageReceived(NextFilter nextFilter, IoSession session, Object message) throws SSLException {
        try {
            System.out.println("In ssl filter:" + message.toString());
            super.messageReceived(nextFilter, session, message);
        }catch (Exception e)
        {
            e.printStackTrace();
            session.close(true);
        }
    }

}
