package com.ericsson.dve.custom.authenticationplugin;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

/**
 * @author Mattias Fridh (emasfrh)
 */
public class LdapTreeSearch {
    String ldapSearchBase;

    public LdapTreeSearch(String searchBase) {
        ldapSearchBase = searchBase;
    }

    public boolean findUserInLdapTree(String username, LdapContext context) throws NamingException {
        SearchControls controls = new SearchControls();
        controls.setReturningAttributes(new String[] { "givenName", "sn", "uid" });
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> answers = context.search(ldapSearchBase, "(uid=" + username + ")", controls);
        while(answers.hasMore()){
        	   SearchResult result = answers.nextElement();
        	   System.out.println("user "+username+" found!");
        	   System.out.println(result.getNameInNamespace());
        	   return true;
        }
     
        System.out.println("user "+username+" not found!");

        return false;
    }
    public static void plainSearch(){
    	//plain search 
    	String base="o=tt,c=cn";
    	LdapContextCreator creater = new LdapContextCreator("ldap://localhost:389/");
    	String adminusername = "cn=Manager,o=tt,c=cn";
    	String adminpass = "secret";
    	String username="ehanmqi";
    	LdapContext ctx =null;
    	try {
    		 ctx = creater.getLdapContext(adminusername, adminpass);
    		 LdapTreeSearch searchEnv = new LdapTreeSearch(base);
    		 searchEnv.findUserInLdapTree(username,ctx);
    		
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			 try {
				ctx.close();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
    }
    
    public static void TLSSearch(){
    	//plain search 
    	String base="o=tt,c=cn";
    	LdapContextCreator creater = new LdapContextCreator("ldap://localhost:636/");
    	String adminusername = "cn=Manager,o=tt,c=cn";
    	String adminpass = "secret";
    	String username="ehanmqi";
    	LdapContext ctx =null;
    	try {
    		 ctx = creater.getSecuredLdapContext(adminusername, adminpass);
    		 LdapTreeSearch searchEnv = new LdapTreeSearch(base);
    		 searchEnv.findUserInLdapTree(username,ctx);
    		
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally{
			 try {
				ctx.close();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
    }
    
    public static void main(String[] arg){
    	//plainSearch();
    	TLSSearch();
    }
    
}
