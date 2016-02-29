/* 
 * Created : 3 nov. 2015
 * 
 * Copyright (c) 2015 Ericsson AB, Sweden. 
 * All rights reserved. 
 * The Copyright to the computer program(s) herein is the property of Ericsson AB, Sweden. 
 * The program(s) may be used and/or copied with the written permission from Ericsson AB 
 * or in accordance with the terms and conditions stipulated in the agreement/contract 
 * under which the program(s) have been supplied. 
 * updated by hanming.qin @20160204
 */

package com.ericsson.dve.custom.authenticationplugin;

import java.io.File;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.dve.common.DVEException;
import com.ericsson.dve.security.AuthenticationPlugin;
import com.ericsson.util.PropertyParser;

/**
 * Example customer adaption authentication implementation. The example shows
 * how an LDAP server could be used to authenticate users in EMA.
 *
 * @author epkjoja
 * @author Mattias Fridh (emasfrh)
 * @auther hanming.qin
 */
public class CustomAuthenticationPlugin implements AuthenticationPlugin {
	private static final Logger logger = LoggerFactory.getLogger(CustomAuthenticationPlugin.class);

	// The name of the submodule that this plugin will be part of.
	private static final String MODULE_NAME = "DVE-Custom-Authentication-Plugin";

	// The needed property names as they are defined in
	// <module>-module.properties
	private static final String LDAP_SERVER_ADRESS1 = "custom.authenticationplugin.ldapserveraddress1";
	private static final String LDAP_SERVER_ADRESS2 = "custom.authenticationplugin.ldapserveraddress2";
	private static final String LDAP_SEARCH_BASE = "custom.authenticationplugin.ldapsearchbase";
	private static final String ADMIN_USERNAME = "custom.authenticationplugin.adminusername";
	private static final String ADMIN_PASSWORD = "custom.authenticationplugin.adminpassword";
	private static final String SECURITY_PROTOCOL = "custom.authenticationplugin.securityprotocal";
	private static final String USE_CACHE="custom.authenticationplugin.usecache";
	private Hashtable<String, String> properties = new Hashtable<String, String>();
	private Properties props=null;
	private LdapTreeSearch ldapTreeSearch;

	public CustomAuthenticationPlugin() {

		try {
			props = PropertyParser.parse(new File("../lib/ext/" + MODULE_NAME + "-module.properties"));
			logger.info("Properties succecfully parsed!");
			properties.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	        properties.put(Context.PROVIDER_URL, props.getProperty(LDAP_SERVER_ADRESS1));
	        properties.put(Context.SECURITY_PRINCIPAL, props.getProperty(ADMIN_USERNAME));
	        properties.put(Context.SECURITY_CREDENTIALS, props.getProperty(ADMIN_PASSWORD));
	        if(props.getProperty(SECURITY_PROTOCOL)!=null && props.getProperty(SECURITY_PROTOCOL).length()>0){
	        	   properties.put(Context.SECURITY_PROTOCOL,"ssl");
	   		       properties.put("java.naming.ldap.factory.socket", "com.ericsson.dve.custom.authenticationplugin.LDAPSSLFactory");
	        }
	        ldapTreeSearch = new LdapTreeSearch(props.getProperty(LDAP_SEARCH_BASE));
		} catch (IOException e) {
			logger.error("Failed to find the submodule properties file: ", e);
		}

		
	}

	/**
	 * Attempt to authenticate a user with a the provided username and password.
	 *
	 * @param username
	 *            The user's username
	 * @param password
	 *            The user's password
	 *
	 * @return result of the authentication action
	 */
	@Override
	public AuthenticationResult authenticate(String username, String password) {
		logger.info("Custom Authenticate: " + username);
		AuthenticationResult result = AuthenticationResult.VALID;
		
		//authenticate user by cache
		String useCache = props.getProperty(USE_CACHE);
		CacheAgent cacheAgent = CacheAgent.getAgent();
		if(useCache!=null && useCache.equalsIgnoreCase("yes")){		
			String resultCache = cacheAgent.authenticateCACHE(username, password);
			if(CacheAgent.VALID.equals(resultCache)){
				return result;
			}
		}
	

		try {
			result= authenticateLDAP(username, password);
			if (result==AuthenticationResult.VALID) {
				//update the cache
				if(useCache!=null && useCache.equalsIgnoreCase("yes")){		
					cacheAgent.updateCache(username, password);
				}
				return result;
			}
		} catch (NamingException e) {
			logger.info("Authentication in LdapAuthentication failed. Message was: " ,e);
			result = AuthenticationResult.INVALID;
		} catch (DVEException e) {
			logger.info("Authentication in LdapAuthentication failed. Message was: " ,e);
			if (DVEException.ACCESS_DENIED.equals(e.getClassifiedError()) ){
				result = AuthenticationResult.NOSUCHUSER;
			} else {
				result = AuthenticationResult.NOCONNECTION;
			}
		}
		return result;
	}

	private AuthenticationResult authenticateLDAP(String username, String password) throws NamingException, DVEException {
		logger.info("authenticateLDAP start: " + username);
		LdapContext context = null;
		try{
			try{
				context = new InitialLdapContext(properties, null);
			}catch(Exception e){
				logger.error("ldap server1 connection is not established, will check server2",e);
		      
		        //init LdapContext2
		        try{
		        	properties.put(Context.PROVIDER_URL, props.getProperty(LDAP_SERVER_ADRESS2));
		        	context = new InitialLdapContext(properties, null);
		        }catch(Exception ee){
		        	logger.error("ldap server2 connection is also not established, will throw exception",ee);
		        	throw new DVEException(DVEException.COMMUNICATION_ERROR);
		        }
			}

			AuthenticationResult result = ldapTreeSearch.findUserInLdapTree(username,password, context);
			return result;
		}finally{
			if(context!=null){
				context.close();
			}
	
		}
	}
}
