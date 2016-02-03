package com.ericsson.dve.custom.authenticationplugin;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;

/**
 * @author Mattias Fridh (emasfrh)
 */
public class LdapContextCreator {
    String ldapServer;

    public LdapContextCreator(String server) {
        ldapServer = server;
    }

    public LdapContext getLdapContext(String username, String password) throws NamingException {
        Hashtable<String, Object> properties = new Hashtable<String, Object>();
        properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(Context.PROVIDER_URL, ldapServer);
        properties.put(Context.SECURITY_PRINCIPAL, username);
        properties.put(Context.SECURITY_CREDENTIALS, password);

        return new InitialLdapContext(properties, null);
    }
    
    public LdapContext getSecuredLdapContext(String username, String password) throws NamingException {
        Hashtable<String, Object> properties = new Hashtable<String, Object>();
        properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        properties.put(Context.PROVIDER_URL, ldapServer);
        properties.put(Context.SECURITY_PRINCIPAL, username);
        properties.put(Context.SECURITY_CREDENTIALS, password);
        properties.put(Context.SECURITY_PROTOCOL, "ssl");
        properties.put("java.naming.ldap.factory.socket", "com.ericsson.dve.custom.authenticationplugin.LDAPSSLFactory");

        return new InitialLdapContext(properties, null);
    }
}
