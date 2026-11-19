package rules

import "testing"

func TestFileMatchPathPolicyCredentialLocations(t *testing.T) {
	for _, p := range []string{
		"/etc/apt/auth.conf", "/etc/apt/auth.conf.d/90-private", "/etc/apt/auth.conf.d/*.conf", "/etc/apt/auth.conf*",
		"/opt/tomcat/conf/tomcat-users.xml", "/etc/tomcat9/tomcat-users.xml", "/etc/tomcat9/tomcat-users*.xml",
		"/usr/local/etc/tomcat/tomcat-users.xml", "/etc/hostapd/hostapd.conf", "/etc/hostapd/*.conf",
		"/etc/squid/passwords", "/etc/squid/pass*", "/etc/gitlab/gitlab.rb", "/etc/gitlab/*.rb",
		"/etc/phpmyadmin/config-db.php", "/etc/phpmyadmin/config.inc.php",
		"/etc/msmtprc", "/etc/nagios/resource.cfg", "/etc/ssmtp/ssmtp.conf", "/etc/ssmtp/*.conf",
		"/etc/my.cnf", "/etc/my.cnf.d/server.cnf", "/etc/redis.conf", "/etc/containers/auth.json",
		"/etc/snmp/snmpd.conf", "/etc/tomcat9/server.xml", "/opt/tomcat/conf/server.xml",
		"/etc/gitlab-runner/config.toml", "/etc/nslcd.conf", "/etc/pam_ldap.conf", "/etc/libnss-ldap.conf",
	} {
		if err := FileMatchPathAllowed(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"/etc/apt/sources.list", "/etc/apt/apt.conf.d/20auto-upgrades", "/etc/squid/squid.conf", "/etc/nagios/nagios.cfg", "/etc/tomcat9/web.xml"} {
		if err := FileMatchPathAllowed(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
}
