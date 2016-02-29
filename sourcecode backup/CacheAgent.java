package com.ericsson.dve.custom.authenticationplugin;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hazelcast.config.Config;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;

public class CacheAgent {
	private static final Logger logger = LoggerFactory.getLogger(CacheAgent.class);
	public static final String CACHE_NOT_WORK="CACHE_NOT_WORK";
	public static final String VALID="VALID";
	public static final String INVALID="INVALID";
	public static final String NO_USER_IN_CACHE="NO_USER_IN_CACHE";
	private static HazelcastInstance instance;
	/**
	 * Attempt to authenticate a user with a the provided username and password in cache
	 * @param username The user's username
	 * @param password  The user's password
	 * @return result of the authentication action
	 */
	protected  String authenticateCACHE(String username, String password) {
		try {
			initCACHE();
		} catch (Exception e) {
			logger.error("CACHE is initialized failed ",e);
			return CACHE_NOT_WORK;
		}
		
		if(instance!=null){
			Map<String, String> userMapCache = instance.getMap("userCache");
			String passwordFromCache = userMapCache.get(username);
			if(passwordFromCache==null){
				return NO_USER_IN_CACHE;
			}else if(passwordFromCache.equals(password)){
				return VALID;
			}else{
				return INVALID;
			}
		}
		return CACHE_NOT_WORK;
	}
	/**
	 * Attempt to init CACHE
	 */
	private  void initCACHE() throws Exception {
		if (instance == null) {
			Config cfg = new Config();
			NetworkConfig network = cfg.getNetworkConfig();
			JoinConfig join = network.getJoin();
			join.getMulticastConfig().setEnabled(true);
			String ip = "";
			boolean b = isServerClustered();
			if (b) {
				ip = getInternalIP();
			} else {
				ip = getExternalIP();
				network.addOutboundPortDefinition("33300-33400");
			}
			if (ip.length() > 0) {
				String interf = ip.substring(0, ip.lastIndexOf(".")) + ".*";
				network.getInterfaces().setEnabled(true).addInterface(interf);
				instance = Hazelcast.newHazelcastInstance(cfg);
			}
		}
	}
	/**
	 * Attempt to update the cache with a the provided username and password
	 * @param username The user's username
	 * @param password  The user's password
	 */
	protected void updateCache(String username,String password){
		if(instance!=null){
			Map<String, String> userMapCache = instance.getMap("userCache");
			userMapCache.put(username,password);
		}
	}
	/**
	 * Attempt to get the ip address by given filename
	 * @param filename The filename of given file
	 * @return ip address of given file
	 */
	private  String getIPAddressByFile(String filename) throws IOException {
		String ip = "";
		BufferedReader bf = null;
		try {
			FileReader fr = new FileReader(filename);
			bf = new BufferedReader(fr);
			while (true) {
				String line = bf.readLine();
				if (line == null) {
					ip = "";
					break;
				}
				if (line != null && line.length() > 0) {
					ip = line.trim();
					break;
				}

			}
		} catch (FileNotFoundException e) {
			throw e;
		} catch (IOException e) {
			throw e;
		} finally {
			try {
				bf.close();
			} catch (IOException e) {
				logger.error(filename+"file can not be closed", e);
			}
		}

		return ip;
	}
	/**
	 * Attempt to get the external ip address by given filename
	 * @return  external ip address of given file
	 */
	private  String getExternalIP() throws IOException {
		logger.info("Get External IP start");
		return getIPAddressByFile("/etc/cluster/nodes/all/1/networks/external/primary/address");
	}
	/**
	 * Attempt to get the intelnal ip address by given filename
	 * @return  internal ip address of given file
	 */
	private  String getInternalIP() throws IOException {
		logger.info("Get Internal ip start");
		return getIPAddressByFile("/etc/cluster/nodes/all/1/networks/internal/primary/address");
	}
	/**
	 * Attempt to check server is clustered or not .
	 * @return result true if sever have folder /etc/cluster/nodes/all  and subfolder
	 */
	private  boolean isServerClustered() throws Exception {
		File file = new File("/etc/cluster/nodes/all");
		if (file.list() != null) {

			if (file.list().length > 1) {
				return true;
			} else {
				return false;
			}
		} else {
			logger.error("server is not clustered");
			throw new Exception("server is not clustered");
		}
	}
	
	public static CacheAgent getAgent(){
		return new CacheAgent();
	}
}
