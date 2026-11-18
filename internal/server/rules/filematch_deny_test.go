package rules

import "testing"

func TestFileMatchPathPolicyCredentialLocations(t *testing.T) {
	for _, p := range []string{
		"/etc/apt/auth.conf", "/etc/apt/auth.conf.d/90-private", "/etc/apt/auth.conf.d/*.conf", "/etc/apt/auth.conf*",
		"/opt/tomcat/conf/tomcat-users.xml", "/etc/tomcat9/tomcat-users.xml", "/etc/tomcat9/tomcat-users*.xml",
		"/usr/local/etc/tomcat/tomcat-users.xml", "/etc/hostapd/hostapd.conf", "/etc/hostapd/*.conf",
		"/etc/squid/passwords", "/etc/squid/pass*", "/etc/gitlab/gitlab.rb", "/etc/gitlab/*.rb",
		"/etc/phpmyadmin/config-db.php", "/etc/msmtprc", "/etc/nagios/resource.cfg", "/etc/ssmtp/ssmtp.conf",
		"/etc/ssmtp/*.conf",
	} {
		if err := FileMatchPathAllowed(p); err == nil {
			t.Errorf("accepted %q", p)
		}
	}
	for _, p := range []string{"/etc/apt/sources.list", "/etc/apt/apt.conf.d/20auto-upgrades", "/etc/squid/squid.conf", "/etc/nagios/nagios.cfg"} {
		if err := FileMatchPathAllowed(p); err != nil {
			t.Errorf("rejected %q: %v", p, err)
		}
	}
}
