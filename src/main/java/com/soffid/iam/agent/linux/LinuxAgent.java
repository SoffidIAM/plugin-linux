// Copyright (c) 2000 Govern  de les Illes Balears
package com.soffid.iam.agent.linux;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.DispatcherAccessControl;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.util.TimedOutException;
import es.caib.seycon.util.TimedProcess;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.ng.comu.ControlAcces;
import es.caib.seycon.ng.comu.DadaUsuari;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.remote.RemoteServiceLocator;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AccessControlMgr;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.GroupMgr;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.RoleInfo;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserInfo;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.db.LogInfoConnection;

/**
 * Agente to manage Zarafa server
 * <P>
 * 
 */

public class LinuxAgent extends Agent implements UserMgr, RoleMgr, GroupMgr {
	/** zarfa-admin program */
	transient boolean sambaUsers;
	private String shell;
	private String home;
	private final long DELAY = 1000;

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public LinuxAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		sambaUsers = "true".equals(getDispatcher().getParam2());
		shell = getDispatcher().getParam0();
		if (shell == null || shell.isEmpty())
			shell = "/bin/false";
		home = getDispatcher().getParam1();
		if (home.isEmpty())
			home = null;
		log.info("Starting Linux Agent {}", getDispatcher().getCodi(), null);
	}

	private LinuxUserInfo getLinuxUser(String name) throws IOException,
			TimedOutException {
		TimedProcess p = new TimedProcess(DELAY);
		int result = p.exec(new String[] { "getent", "passwd", name}); 
		if ( result == 2) 
			return null;
		else if (result == 0)
		{
			p = new TimedProcess(DELAY);
			if (p.exec(new String[]{"id", "-G", name}) == 0) {
				String out = p.getOutput();
				String groups[]  = out.split("\\s");
				LinuxUserInfo zui = new LinuxUserInfo();
				zui.user = name;
				for (String group: groups)
				{
					zui.groups.add(group);
				}
				return zui;
			} else {
				if (p.getError().indexOf("not found") >= 0)
					return null;
				else
					throw new IOException("Error executing id :"
							+ p.getError());
			}
		} else {
			throw new IOException("Error executing getent :"
					+ p.getError());
		}
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String codiCompte, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			// Obtener los datos del usuario
			Collection<RolGrant> roles = getServer().getAccountRoles(
					codiCompte, this.getDispatcher().getCodi());

			Collection<Grup> groups;
			if (getDispatcher().getBasRol()) {
				groups = null;
			} else {
				groups = getServer().getUserGroups(usu.getId());
			}
			LinkedList<String> groupsAndRoles = concatUserGroupsAndRoles(groups, roles);

			// Comprobar si el usuario existe
			LinuxUserInfo linuxUser = getLinuxUser(codiCompte);
			if (linuxUser == null) {
				LinkedList<String> args = new LinkedList<String>();
				args.add("useradd");
				args.add("-c");
				args.add(usu.getFullName());
				if (home != null)
				{
					args.add("-b");
					args.add(home);
					args.add ("-m");
				}
				if (!groupsAndRoles.isEmpty())
				{
					args.add("-G");
					StringBuffer sb = new StringBuffer();
					for (String gor: groupsAndRoles)
					{
						if (sb.length() > 0)
							sb.append (",");
						sb.append (gor);
					}
					args.add(sb.toString());
				}
				args.add ("--shell");
				args.add (shell);
				args.add(codiCompte);

				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing useradd -c: "+p.getError());
				}
				updateUserPassword (codiCompte, usu, getServer().getOrGenerateUserPassword(codiCompte, getCodi()), false);
			}
			else
			{
				LinkedList<String> args = new LinkedList<String>();
				args.add("usermod");
				args.add("-U");
				args.add("-c");
				args.add(usu.getFullName());
				args.add("-e");
				args.add("");
				args.add("-G");
				StringBuffer sb = new StringBuffer();
				for (String gor: groupsAndRoles)
				{
					if (sb.length() > 0)
						sb.append (",");
					sb.append (gor);
				}
				args.add(sb.toString());
				args.add ("--shell");
				args.add (shell);
				args.add(codiCompte);

				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing usermod -c: "+p.getError());
				}
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	private String getEmail(Usuari usu) throws InternalErrorException, es.caib.seycon.ng.exception.UnknownUserException {
		if (usu.getNomCurt() != null)
			return usu.getNomCurt()+"@"+usu.getDominiCorreu();
		DadaUsuari data = getServer().getUserData(usu.getId(), "EMAIL");
		if (data != null)
			return data.getValorDada();
		else
			return null;
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String user, Usuari usuari, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		try {
			LinuxUserInfo zui = getLinuxUser(user);
			if (zui == null)
				updateUser(user, usuari);
			
			LinkedList<String> args = new LinkedList<String>();
			args.add("passwd");
			args.add(user);
			TimedProcess p = new TimedProcess(DELAY);
			p.execNoWait(args.toArray(new String[args.size()]));
			p.consumeError();
			p.consumeOutput();
			OutputStream out = p.getInputStream();
			PrintStream pout = new PrintStream(out);
			pout.println(password.getPassword());
			pout.println(password.getPassword());
			pout.close();
			if (p.join() != 0)
			{
				throw new InternalErrorException("Error executing passwd: "+p.getError());
			}
			if (mustchange)
			{
				p = new TimedProcess(DELAY);
				p.exec (new String [] {"passwd", "-e", user});
			}
			if (sambaUsers)
			{
				p = new TimedProcess(DELAY);
				p.execNoWait(new String[] {"smbpasswd", "-a", user});
				p.consumeError();
				p.consumeOutput();
				out = p.getInputStream();
				pout = new PrintStream(out);
				pout.println(password.getPassword());
				pout.println(password.getPassword());
				pout.close();
				if (p.join() != 0)
				{
					throw new InternalErrorException("Error setting samba password "+p.getError());
				}
				p = new TimedProcess(DELAY);
				if (p.exec(new String[] {"smbpasswd", "-e", user}) != 0)
				{
					throw new InternalErrorException("Error enable samba password "+p.getError());
				}
				
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups
	 *            vector de grupos
	 * @param roles
	 *            vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public LinkedList<String> concatUserGroupsAndRoles(Collection<Grup> groups,
			Collection<RolGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getDispatcher().getBasRol()) // roles.length == 0
															// && getRoleBased
															// ()
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Grup g : groups)
				concat.add(g.getCodi());
		}
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat;
	}

	public String[] concatRoleNames(Collection<RolGrant> roles) {
		if (roles.isEmpty() && getDispatcher().getBasRol())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Rol ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (ri.getBaseDeDades().equals (getCodi()))
		{
			try {
				LinkedList<String> args = new LinkedList<String>();
				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(new String[] { "getent", "group", ri.getNom()}) != 0)
				{
					p = new TimedProcess(DELAY);
					p.exec (new String [] {"groupadd", ri.getNom()});
				}
			} catch (RemoteException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (TimedOutException e) {
				throw new InternalErrorException("Error update password", e);
			}
		}
	}


	public void removeRole(String nom, String bbdd) throws InternalErrorException {
		if (bbdd.equals (getCodi()))
		{
			try {
				LinkedList<String> args = new LinkedList<String>();
				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(new String[] { "getent", "group", nom}) == 2) // Not found
				{
					p = new TimedProcess(DELAY);
					p.exec (new String [] {"groupdel", nom});
				}
			} catch (RemoteException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (IOException e) {
				throw new InternalErrorException("Error update password", e);
			} catch (TimedOutException e) {
				throw new InternalErrorException("Error update password", e);
			}
		}
	}

	public void removeUser(String user) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			LinuxUserInfo zui = getLinuxUser(user);
			if (zui != null)
			{
				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(new String[] { "usermod", "-e", "1", "-L", user}) != 0)
				{
					throw new InternalErrorException("Error executing zarafa-admin -c: "+p.getError());
				}
				if (sambaUsers)
				{
					p = new TimedProcess(DELAY);
					if (p.exec(new String[] {"smbpasswd", "-x", user}) != 0)
					{
						if (!p.getError().contains("Failed to find entry"))
							throw new InternalErrorException("Error enable samba password "+p.getError());
					}
					
				}
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	public void updateUser(String account, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			// Obtener los datos del usuario
			Collection<RolGrant> roles = getServer().getAccountRoles(
					account, this.getDispatcher().getCodi());

			LinkedList<String> groupsAndRoles = concatUserGroupsAndRoles(null, roles);

			// Comprobar si el usuario existe
			LinuxUserInfo linuxUser = getLinuxUser(account);
			if (linuxUser == null) {
				LinkedList<String> args = new LinkedList<String>();
				args.add("useradd");
				args.add("-c");
				args.add(descripcio);
				if (home != null)
				{
					args.add("-b");
					args.add(home);
					args.add ("-m");
				}
				if (!groupsAndRoles.isEmpty())
				{
					args.add("-G");
					StringBuffer sb = new StringBuffer();
					for (String gor: groupsAndRoles)
					{
						if (sb.length() > 0)
							sb.append (",");
						sb.append (gor);
					}
					args.add(sb.toString());
				}
				args.add ("--shell");
				args.add (shell);
				args.add(account);

				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing useradd -c: "+p.getError());
				}
				updateUserPassword (account, null, getServer().getOrGenerateUserPassword(account, getCodi()), false);
			}
			else
			{
				LinkedList<String> args = new LinkedList<String>();
				args.add("usermod");
				args.add("-U");
				args.add("-c");
				args.add(descripcio);
				args.add("-e");
				args.add("");
				args.add("-G");
				StringBuffer sb = new StringBuffer();
				for (String gor: groupsAndRoles)
				{
					if (sb.length() > 0)
						sb.append (",");
					sb.append (gor);
				}
				args.add(sb.toString());
				args.add ("--shell");
				args.add (shell);
				args.add(account);

				TimedProcess p = new TimedProcess(DELAY);
				if (p.exec(args.toArray(new String[args.size()])) != 0)
				{
					throw new InternalErrorException("Error executing usermod -c: "+p.getError());
				}
			}
			
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error processing task", e);
		}
	}

	public void updateGroup(String nom, Grup grup) throws RemoteException,
			InternalErrorException {
		try {
			LinkedList<String> args = new LinkedList<String>();
			TimedProcess p = new TimedProcess(DELAY);
			if (p.exec(new String[] { "getent", "group", nom}) != 0)
			{
				p = new TimedProcess(DELAY);
				p.exec (new String [] {"groupadd", nom});
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}

	public void removeGroup(String nom) throws RemoteException,
			InternalErrorException {
		try {
			LinkedList<String> args = new LinkedList<String>();
			TimedProcess p = new TimedProcess(DELAY);
			if (p.exec(new String[] { "getent", "group", nom}) == 2) // Not found
			{
				p = new TimedProcess(DELAY);
				p.exec (new String [] {"groupdel", nom});
			}
		} catch (RemoteException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (IOException e) {
			throw new InternalErrorException("Error update password", e);
		} catch (TimedOutException e) {
			throw new InternalErrorException("Error update password", e);
		}
	}
}

class LinuxUserInfo {
	String user;
	Collection<String> groups = new LinkedList<String>();
}
