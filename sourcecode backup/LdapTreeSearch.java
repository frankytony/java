package com.ericsson.dve.custom.authenticationplugin;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.dve.security.AuthenticationPlugin.AuthenticationResult;

/**
 * @author Mattias Fridh (emasfrh)
 * @author hanming.qin
 */
public class LdapTreeSearch {
	private static final Logger logger = LoggerFactory.getLogger(LdapTreeSearch.class);
	String ldapSearchBase;

	public LdapTreeSearch(String searchBase) {
		ldapSearchBase = searchBase;
	}

//	public String findUserInLdapTree(String username, LdapContext context) throws NamingException {
//		SearchControls controls = new SearchControls();
//		controls.setReturningAttributes(new String[] { "givenName", "sn", "uid" });
//		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//
//		NamingEnumeration<SearchResult> answers = context.search(ldapSearchBase, "(uid=" + username + ")", controls);
//		while (answers.hasMore()) {
//			SearchResult result = answers.nextElement();
//			logger.info("user " + username + " found!");
//			return result.getNameInNamespace();
//		}
//
//		logger.info("user " + username + " not found!");
//
//		return null;
//	}
	public AuthenticationResult findUserInLdapTree(String username, String password,LdapContext context) throws NamingException{
		SearchControls controls = new SearchControls();
		controls.setReturningAttributes(new String[] { "sn", "uid" ,"userPassword"});
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration<SearchResult> answers = context.search(ldapSearchBase, "(uid=" + username + ")", controls);
		while (answers.hasMore()) {
			SearchResult result = answers.nextElement();
			logger.info("user info" , result);
			logger.info("user " + username + " found!");
			//String DN = result.getNameInNamespace();
//			context.addToEnvironment(javax.naming.Context.SECURITY_PRINCIPAL,  DN);
//			context.addToEnvironment(javax.naming.Context.SECURITY_CREDENTIALS,  password);
//			context.reconnect(null);
			String filter = "(&(uid=" + username + ")(userPassword="+password+"))";
			NamingEnumeration<SearchResult> answersVerifyUserPass = context.search(ldapSearchBase,filter, controls);
			while (answersVerifyUserPass.hasMore()) {
				logger.info("user " + username + " and pass correct!");
				return AuthenticationResult.VALID;
			}
			return AuthenticationResult.INVALID;
		}
		logger.info("User not found in backend database.");
		return AuthenticationResult.NOSUCHUSER;
	}
	
//	public String findUserInLdapTreeByIDandPass(String username,String password, LdapContext context) throws NamingException {
//		SearchControls controls = new SearchControls();
//		controls.setReturningAttributes(new String[] { "userPassword", "sn", "uid" });
//		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//		String filter = "(&(uid=" + username + ")(userPassword="+password+"))";
//		NamingEnumeration<SearchResult> answers = context.search(ldapSearchBase,filter, controls);
//		while (answers.hasMore()) {
//			SearchResult result = answers.nextElement();
//			logger.info("user " + username + " found!");
//			return result.getNameInNamespace();
//		}
//
//		logger.info("user " + username + " not found!");
//
//		return null;
//	}

//	public static void plainSearch() {
//		// plain search
//		String base = "o=tt,c=cn";
//		LdapContextCreator creater = new LdapContextCreator("ldap://localhost:389/");
//		String adminusername = "cn=Manager,o=tt,c=cn";
//		String adminpass = "secret";
//		String username = "ehanmqi";
//		LdapContext ctx = null;
//		try {
//			ctx = creater.getLdapContext(adminusername, adminpass);
//			LdapTreeSearch searchEnv = new LdapTreeSearch(base);
//			searchEnv.findUserInLdapTree(username, ctx);
//
//		} catch (NamingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} finally {
//			try {
//				ctx.close();
//			} catch (NamingException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
//	}
//
//	public static void TLSSearch() {
//		// plain search
//		String base = "o=tt,c=cn";
//		LdapContextCreator creater = new LdapContextCreator("ldap://localhost:636/");
//		String adminusername = "cn=Manager,o=tt,c=cn";
//		String adminpass = "secret";
//		String username = "ehanmqi";
//		LdapContext ctx = null;
//		try {
//			ctx = creater.getSecuredLdapContext(adminusername, adminpass);
//			LdapTreeSearch searchEnv = new LdapTreeSearch(base);
//			searchEnv.findUserInLdapTree(username, ctx);
//
//		} catch (NamingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} finally {
//			try {
//				ctx.close();
//			} catch (NamingException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
//	}
//
//	public static void main(String[] arg) {
//		// plainSearch();
//		TLSSearch();
//	}

}
