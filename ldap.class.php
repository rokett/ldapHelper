<?php
class ldap {

	// LDAP Connection
	protected $connection = null;

	// Result of bind to LDAP connection (true or false)
	protected $bind = null;

	// base DN
	protected $baseDN;

	/**
	 * Create a connection to LDAP and set the baseDN
	 *
	 * @param	string	$host			LDAP host to connect to
	 * @param	string	$ldapUsername	Username to connect to LDAP host with. Should be in the format username@domain.
	 * @param	string	$ldapPassword	Password for connecting to LDAP host.
	 */
	public function __construct($host, $ldapUsername = null, $ldapPassword = null) {
		$this->connection = ldap_connect($host);

		// Following options need to be set when working with Active Directory
		ldap_set_option($this->connection, LDAP_OPT_REFERRALS, 0);
		ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, 3);

		$this->bind = ldap_bind($this->connection, $ldapUsername, $ldapPassword);

		// Get the root baseDN
		$this->baseDN = $this->findBaseDN();
	}

	/**
	 * Find baseDN for LDAP domain
	 *
	 * @return	string	baseDN
	 */
	protected function findBaseDN() {
		$defaultNamingContext = $this->getRootDse(array('defaultNamingContext'));
		return $defaultNamingContext[0]['defaultnamingcontext'][0];
	}

	/**
	 * Get Root DSE
	 *
	 * @param	array	Attributes to return.  By default all attributes will be returned
	 * @return	array	Requested attributes
	 */
	protected function getRootDse($attributes = null) {
		if ($attributes === null) {
			$result = ldap_read($this->connection, NULL, 'objectClass=*');
		} else {
			$result = ldap_read($this->connection, NULL, 'objectClass=*', $attributes);
		}
		
		$entries = ldap_get_entries($this->connection, $result);
		return $entries;
	}

	/**
	 * Get user object information
	 *
	 * @param	string	$username	Username (sAMAccountName) to search for
	 * @param	string	$baseDN		Base to search from.  If baseDN is not passed, the root baseDN will be used
	 * @param	array	$attributes	Attributes to return.  By default all attributes will be returned
	 * @return	array	Requested attributes
	 */
	public function getUserDetails($username = null, $baseDN = null, $attributes = null) {
		$filter = '(&(objectCategory=Person)(sAMAccountName=' . $username . '))';

		if ($baseDN === null) {
			$baseDN = $this->baseDN;
		}

		if ($attributes === null) {
			$result = ldap_search($this->connection, $baseDN, $filter);
		} else {
			$result = ldap_search($this->connection, $baseDN, $filter, $attributes);
		}
		
        $entries = ldap_get_entries($this->connection, $result);

        return $entries;
	}
}
