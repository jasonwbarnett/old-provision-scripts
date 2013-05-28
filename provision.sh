#!/bin/bash

## Set some environment variables.
PROVISION_ROOT=/root/.company/provision
JBARNETT_SCRIPTS=/root/.jbarnett_scripts

## Install mailx and sendmail so we can send initial email.
yum -y install mailx sendmail
/sbin/service sendmail restart

## EMAIL VARIABLES AND STUFF
SUBJECT="$(hostname) Provision Process"
EMAIL="jbarnett@company.com"

## Send START email
echo "START" | mail -s "${SUBJECT}" "${EMAIL}"


## Create some folders for place holders
mkdir -p /opt/CUSTOMIZATIONS/INSTALLS
echo  > /opt/CUSTOMIZATIONS/INSTALLS/install.log
echo Creating necessary directories  >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
mkdir -p /root/.company
mkdir -p "${PROVISION_ROOT}"
mkdir -p /opt/CUSTOMIZATIONS/OTHER
mkdir -p /opt/CUSTOMIZATIONS/TOMCAT
mkdir -p /root/packages
mkdir -p /opt/webapps
mkdir -p /opt/dbbackups
mkdir -p /opt/archives


## Set root as owner for all files under provision root.
chown -R root:root "${PROVISION_ROOT}"


## Extract .jbarnett_scripts to it's proper directory
mv "${PROVISION_ROOT}"/.jbarnett_scripts.tar.gz /root/
cd /root && tar -zxvf .jbarnett_scripts.tar.gz


## Copy find_unused_ips.sh to sbin.
cp /root/.jbarnett_scripts/find_unused_ips.sh /sbin/


## Copy mk-find to /usr/local/bin/
cp "${JBARNETT_SCRIPTS}/usr/local/bin/mk-find" /usr/local/bin/


## Install a bunch of stuff.
yum -y --disableexcludes=all install compat-gcc-34 compat-libstdc++-33 expect \
   ImageMagick-perl kernel-devel bind-utils \
   sharutils system-config-kickstart mutt \
   xinetd xorg-x11-deprecated-libs yumex perl-Net-SSLeay \
   rsync openssl httpd mysql-server perl-Crypt-SSLeay \
   perl-Net-SSLeay system-config-securitylevel-tui \
   system-config-network unzip php php-mysql libmcrypt \
   php-mcrypt php-mbstring perl-Geo-IP php-gd system-config-date \
   postfix-pflogsumm libselinux mailx which slocate \
   cyrus-sasl-* xorg-x11-fonts-* fonts-* sysstat wireshark \
   vim-enhanced


# Install additional yum repositories and disable them.
rpm -Uvh "${PROVISION_ROOT}/packages/rpmforge-release-0.5.1-1.el5.rf.x86_64.rpm" "${PROVISION_ROOT}/packages/epel-release-5-4.noarch.rpm"
sed -i 's#^enabled.*1$#enabled=0#g' /etc/yum.repos.d/rpmforge.repo /etc/yum.repos.d/epel.repo

## Put company repo conf into place.
cp "${JBARNETT_SCRIPTS}/etc/yum.repos.d/company.repo" /etc/yum.repos.d/company.repo

## Add more global excludes to yum.conf
if [[ $(grep '^exclude=' /etc/yum.conf) ]]
    then
        sed -i 's#^exclude=.*#exclude=kernel* mysql* fuse* rlog#g' /etc/yum.conf
    else
        echo -e "\nexclude=kernel* mysql* fuse* rlog" >> /etc/yum.conf
fi


## Install packages that require rpmforge and epel repo's.
yum -y --enablerepo=rpmforge,epel install git iftop unrar htop


## Update "locate" database.
updatedb


## Run yum update
yum -y update


## Make network start at boot and turn off NetworkManager
if [[ -s /etc/rc.d/init.d/NetworkManager ]]; then
/sbin/chkconfig NetworkManager off
/sbin/chkconfig network on
/sbin/service NetworkManager stop
/sbin/service network restart
fi

## Make ntpd start at boot.
/sbin/chkconfig ntpd on
/sbin/service ntpd restart


## Install shutdown-email-notification service
cp "${JBARNETT_SCRIPTS}/etc/init.d/shutdown-email-notification" /etc/init.d
chkconfig shutdown-email-notification on


## Move *.company.com cert into place
mv "${PROVISION_ROOT}"/star_company_com.key /etc/pki/tls/private/star_company_com.key
mv "${PROVISION_ROOT}"/star_company_com.crt /etc/pki/tls/certs/star_company_com.crt


## Place pflogsumm-daily-report in cron.daily for Daily Mail Stats.
cp "${JBARNETT_SCRIPTS}/etc/cron.daily/pflogsumm-daily-report" /etc/cron.daily


## Configure MySQL Server.
echo Install MySQL >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
chkconfig mysqld on
/sbin/service mysqld restart
# create mysql logs directory for the binary logs
mkdir -p /var/lib/mysqllogs && chown mysql.mysql /var/lib/mysqllogs
# Change MySQL root password to PASSWORD
mysqladmin -u root password PASSWORD
# Remove root user's .my.cnf file and replace it with the standard provision one.
rm -f /root/.my.cnf
cp -f "${JBARNETT_SCRIPTS}/root/.my.cnf" /root/.my.cnf



## MySQL hardening.
"${PROVISION_ROOT}"/mysql_secure_installation.exp PASSWORD n y n y y

/sbin/service mysqld restart

DB_PASSWORD="PASSWORD"

## Create a backup of the original my.cnf file and put in place the templated file.
mv -f /etc/my.cnf /etc/my.cnf.original
cp -f "${JBARNETT_SCRIPTS}/etc/my.cnf" /etc/my.cnf


## Move the my.cnf file over for easy backup
mv /etc/my.cnf /opt/CUSTOMIZATIONS/OTHER/my.cnf
ln -s /opt/CUSTOMIZATIONS/OTHER/my.cnf /etc/my.cnf
chmod 644 /etc/my.cnf
chown root.root /etc/my.cnf


## Set proper permissions for /tmp
chown root:root /tmp
chmod 1777 /tmp


## Remove InnoDB log files so that there isn't a mismatch in file size. MySQL will recreate them as soon as it restarts.
rm -f /var/lib/mysql/ib_logfile*
/sbin/service mysqld restart


## Create the company mysql user
mysql -uroot -e "GRANT ALL PRIVILEGES ON *.* TO company IDENTIFIED BY 'PASSWORD' WITH GRANT OPTION; FLUSH PRIVILEGES;"
mysql -uroot -e "update mysql.user set password=PASSWORD('PASSWORD') where User='root'; FLUSH PRIVILEGES;"
touch /root/.company/mysql-my.cnf-configured


## Run through mysql_upgrade script in case mysql-server was installed by default and updated during yum updates.
/usr/bin/mysql_upgrade


## Created user and group accounts.
echo Creating groups and user accounts >> /opt/CUSTOMIZATIONS/INSTALLS/install.log

groupadd company

useradd -c 'company software user. www.company.com' -g company company

if [[ $(id jbarnett &> /dev/null) ]]; then userdel -r jbarnett; fi

## Users with root access
useradd -c 'First Last' -gcompany -Gwheel filname


## Everyone else
useradd -c 'First Last' -gcompany filname


## User for cacti service
useradd cacti


echo Modifying sshd config   >> /opt/CUSTOMIZATIONS/INSTALLS/install.log

# Change the location of the Authorized Key in the sshd config file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.original
grep -Evi 'Port|PermitRootLogin|AuthorizedKeysFile|UseDNS|#Port|#PermitRootLogin|#AuthorizedKeysFile|#UseDNS' /etc/ssh/sshd_config > /etc/ssh/sshd_config.temp
mv -f /etc/ssh/sshd_config.temp /etc/ssh/sshd_config && rm -f /etc/ssh/sshd_config.temp
chkconfig sshd on
cd /etc/ssh/
echo -e "\nAuthorizedKeysFile      /etc/ssh/keys/%u\nUseDNS no\nPort 30022\nPermitRootLogin yes" >> /etc/ssh/sshd_config
mv /etc/ssh/sshd_config /opt/CUSTOMIZATIONS/OTHER/sshd_config
cd /etc/ssh/
ln -s /opt/CUSTOMIZATIONS/OTHER/sshd_config .
ls -la # Confirm the location of the file
diff sshd_config sshd_config.original

## Put sudoers file in place.
if [[ $(alias | grep -q 'cp=') ]]; then unalias cp; fi  # We do this so it doesn't prompt us to overwrite.
cp -f /root/.jbarnett_scripts/etc/sudoers /etc/sudoers
chown root:root /etc/sudoers
chmod 0440 /etc/sudoers
alias cp='cp -i'


echo Importing key files for automated access   >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
mkdir /etc/ssh/keys/
rsync -avzp "${PROVISION_ROOT}"/keys/ /etc/ssh/keys/


echo Configuring the firewall   >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
lokkit --quiet --selinux='disabled' --disabled
touch /root/.company/firewall-configured

echo Taking newinstall snapshots  >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
df -k > /opt/CUSTOMIZATIONS/INSTALLS/df-k-newinstall.txt
ls -laR > /opt/CUSTOMIZATIONS/INSTALLS/ls-laR-newinstall.txt
rpm -qa > /opt/CUSTOMIZATIONS/INSTALLS/rpm-qa-newinstall.txt
ls -la /opt/CUSTOMIZATIONS/INSTALLS/
# Save the dmesg boot output in a file for the future
echo Saving dmesg boot output  >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
dmesg > /opt/CUSTOMIZATIONS/INSTALLS/dmesg-boot.txt


## Set vi as the default editor.
echo Setting vi to be the editor >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
egrep '^export EDITOR' /root/.bash_profile
if [ $? == 1  ]
  then
    cp /root/.bash_profile /root/.bash_profile_original
    echo 'export EDITOR=vi' >> /root/.bash_profile
    mv /root/.bash_profile /opt/CUSTOMIZATIONS/OTHER/root_bash_profile
    ln -s /opt/CUSTOMIZATIONS/OTHER/root_bash_profile /root/.bash_profile
    diff /root/.bash_profile /root/.bash_profile_original
fi

## Turn off unnecessary daemons.
echo Turning off some daemons >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
chkconfig setroubleshoot off
chkconfig bluetooth off
chkconfig xend off


## Install JDK
yum -y --nogpgcheck --enablerepo=company install jdk

## Make Sun the default JDK
echo Make Sun the default JDK >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
echo "export JAVA_HOME=/usr/java/latest" > /opt/CUSTOMIZATIONS/OTHER/java.sh
echo "export PATH=\$JAVA_HOME/bin:\$PATH" >> /opt/CUSTOMIZATIONS/OTHER/java.sh
chmod 755 /opt/CUSTOMIZATIONS/OTHER/java.sh
ln -s /opt/CUSTOMIZATIONS/OTHER/java.sh /etc/profile.d/java.sh


## Setup disk space alerts
cp "${JBARNETT_SCRIPTS}/etc/cron.daily/diskAlert" /etc/cron.daily && chmod 755 /etc/cron.daily/diskAlert


## Configure sendmail
echo Configure Sendmail >> /opt/CUSTOMIZATIONS/INSTALLS/install.log
cd /etc/mail
mv /etc/mail/sendmail.cf /etc/mail/sendmail.cf.original
cat /etc/mail/sendmail.cf.original  | sed -r -e "s/^#O MatchGECOS/O MatchGECOS/" > /tmp/sendmail.tmp
cat /tmp/sendmail.tmp | sed -r -e "s/^O DaemonPortOptions/#O DaemonPortOptions/" > /opt/CUSTOMIZATIONS/OTHER/sendmail.cf
rm -f /tmp/sendmail.tmp
ln -s /opt/CUSTOMIZATIONS/OTHER/sendmail.cf sendmail.cf
chmod 644 sendmail.cf
touch /root/.company/sendmail-configured
/sbin/service sendmail restart


## Stop sendmail, install postfix, make postfix start at boot
/sbin/service sendmail stop
chkconfig sendmail off
yum -y install postfix
chkconfig postfix on
/sbin/service postfix restart


## Put header checks file into place.
cp "${JBARNETT_SCRIPTS}/etc/postfix/header_checks.regexp.production" /etc/postfix/header_checks.regexp


## Setup postfix to use SocketLabs as a SMTP relay
postconf -e 'relayhost = smtp.socketlabs.com'
postconf -e 'smtp_sasl_auth_enable = yes'
postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
postconf -e 'smtp_sasl_security_options ='
postconf -e 'smtp_sasl_mechanism_filter ='
postconf -e 'myorigin = company.com'
postconf -e 'masquerade_domains = company.com'
postconf -e 'masquerade_exceptions = root'
postconf -e 'mime_header_checks = regexp:/etc/postfix/header_checks.regexp'
postconf -e 'header_checks = regexp:/etc/postfix/header_checks.regexp'
echo "smtp.socketlabs.com   jbarnett:PASSWORD" > /etc/postfix/sasl_passwd
chown root:root /etc/postfix/sasl_passwd && chmod 600 /etc/postfix/sasl_passwd
postmap /etc/postfix/sasl_passwd && rm -f /etc/postfix/sasl_passwd
/sbin/service postfix restart


# Setup root mail to go to root@company.com
cp /etc/aliases /etc/aliases.original
sed -i 's#^root.*#root: root@company.com#g' /etc/aliases
sed -i 's#^backup.*#backup: backup@company.com#g' /etc/aliases
/sbin/service postfix restart


# Install tomcat
yum -y --enablerepo=company install tomcat-6.0.18-2
chkconfig tomcat on

cd /opt/tomcat/conf
cp /opt/tomcat/conf/server.xml /opt/tomcat/conf/server.xml.original
cp "${PROVISION_ROOT}/linux-server.xml" server.xml.company
# diff server.xml.company server.xml.original


SECOND_IP=`ifconfig -a | grep 'inet addr:' | tr -s " " | sed 's/^[ ]//g' | cut -d' ' -f 2 | cut -d':' -f 2 | head -2 | tail -1`
echo ${SECOND_IP}

# Configure Tomcat
cd /opt/tomcat/conf
echo "" > sed_cmds
echo "s/(<Connector port=\"8080\" )/\1address=\"${SECOND_IP}\" /" >> sed_cmds
echo "s/10.1.1.1/${SECOND_IP}/" >> sed_cmds
echo "s/DBUSER/company/" >> sed_cmds
echo "s/DBPASSWORD/${DB_PASSWORD}/"  >> sed_cmds
cat sed_cmds
cat server.xml.company | sed -r -f sed_cmds > server.xml


chmod 660 server.xml
chown tomcat.company server.xml
touch /root/.company/tomcat-configured


# Backup a few tomcat files and replace them with updated files.
cp /opt/tomcat/conf/tomcat-env.sh /opt/tomcat/conf/tomcat-env.sh.original
sed -i 's#MaxPermSize=...m#MaxPermSize=768m#g' /opt/tomcat/conf/tomcat-env.sh

mv /usr/java/latest/jre/lib/security/US_export_policy.jar /usr/java/latest/jre/lib/security/US_export_policy.jar.original
cp "${JBARNETT_SCRIPTS}/usr/java/latest/jre/lib/security/US_export_policy.jar" /usr/java/latest/jre/lib/security

mv /usr/java/latest/jre/lib/security/local_policy.jar /usr/java/latest/jre/lib/security/local_policy.jar.original
cp "${JBARNETT_SCRIPTS}/usr/java/latest/jre/lib/security/local_policy.jar" /usr/java/latest/jre/lib/security


# move the tomcat server.xml file to CUSTOMIZATIONS
mv /opt/tomcat/conf/server.xml /opt/CUSTOMIZATIONS/TOMCAT/server.xml
ln -s /opt/CUSTOMIZATIONS/TOMCAT/server.xml /opt/tomcat/conf/server.xml




## Put *.company.com keystore in place.
mkdir -p /opt/tomcat/conf/keystore_csr/
mv -f '/root/.jbarnett_scripts/opt/tomcat/conf/keystore_csr/*.company.com.20100427-1759.keystore' '/opt/tomcat/conf/keystore_csr/*.company.com.20100427-1759.keystore'
if [ -f /opt/tomcat/conf/keystore_csr/company.keystore ]
  then
    rm -f /opt/tomcat/conf/keystore_csr/company.keystore
fi
ln -s '/opt/tomcat/conf/keystore_csr/*.company.com.20100427-1759.keystore' '/opt/tomcat/conf/keystore_csr/company.keystore'
chown -R tomcat.company /opt/tomcat/conf/keystore_csr

## Restart tomcat
/sbin/service tomcat restart

## Replace tomcat init.d script with custom script that notifies us upon any restart
if [ -f /opt/tomcat/bin/tomcat.original ]
  then
    cp "${JBARNETT_SCRIPTS}/opt/tomcat/bin/tomcat" /opt/tomcat/bin/tomcat
    chown tomcat:company /opt/tomcat/bin/tomcat
  else
    mv /opt/tomcat/bin/tomcat /opt/tomcat/bin/tomcat.original
    cp "${JBARNETT_SCRIPTS}/opt/tomcat/bin/tomcat" /opt/tomcat/bin/tomcat
    chown tomcat:company /opt/tomcat/bin/tomcat
fi


cp -b "${JBARNETT_SCRIPTS}/opt/tomcat/conf/manager.xml" /opt/tomcat/conf/manager.xml

cd /etc/rc.d
cp rc.local rc.local.original
cp rc.local rc.local.tmp

cat >> rc.local.tmp<<EOF

# company's customizations from here down.
modprobe iptable_filter
modprobe iptable_nat

# Second public address: Remap port 80 to 8080, and 443 to 8443.
iptables -t nat -I PREROUTING -p tcp --dst 1.2.3.4 --dport 80 -j DNAT --to 1.2.3.4:8080
iptables -t nat -I OUTPUT -p tcp --dst 1.2.3.4 --dport 80 -j DNAT --to 1.2.3.4:8080
iptables -t nat -I OUTPUT -p tcp --dst 1.2.3.4 --dport 443 -j DNAT --to 1.2.3.4:8443
iptables -t nat -I PREROUTING -p tcp --dst 1.2.3.4 --dport 443 -j DNAT --to 1.2.3.4:8443
EOF


# Do this step only For Rackspace machines
SECOND_IP=`ifconfig -a | grep 'inet addr:' | tr -s " " | sed 's/^[ ]//g' | cut -d' ' -f 2 | cut -d':' -f 2 | head -2 | tail -1` # For Rackspace
echo ${SECOND_IP}
cat rc.local.tmp | sed -r -e "s/1.2.3.4/${SECOND_IP}/g" > rc.local


# Configure iptables.
diff rc.local rc.local.original
rm -Rf rc.local.tmp
# Move the file over
mv /etc/rc.d/rc.local /opt/CUSTOMIZATIONS/OTHER/rc.local
ln -s /opt/CUSTOMIZATIONS/OTHER/rc.local /etc/rc.d/rc.local
ls -la /etc/rc.d
touch /root/.company/iptables-configured


# Configure crontab.
crontab -l >/root/.company/.crontab

cat >> /root/.company/.crontab <<EOF
#min(0-59)
#|      hour(0-23)
#|      |       day of month (1-31)
#|      |       |       month of year(1-12)
#|      |       |       |       day of week (0-6, sunday=0)
#|      |       |       |       |       command
0 */1 * * * chown -R tomcat.company /opt/webapps; chmod -R g+w /opt/webapps
EOF

crontab -u root /root/.company/.crontab
touch /root/.company/crontab-configured


# Install webmin and set it to start at boot.
yum -y --enablerepo=company install webmin
chkconfig webmin on
/sbin/service webmin restart


# Configure webmin and add jbarnett user to access list.
cd /etc/webmin
echo  >> /etc/webmin/miniserv.users
echo jbarnett:x:0 >> /etc/webmin/miniserv.users
echo jbarnett: acl adsl-client apache at backup-config bacula-backup bandwidth bind8 burner cfengine change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dnsadmin dovecot exim exports fdisk fetchmail file filter firewall frox fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec jabber krb5 ldap-client ldap-server ldap-useradmin lilo logrotate lpadmin lvm mailboxes mailcap majordomo man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd pserver qmailadmin quota raid samba sarg sendmail sentry servers shell shorewall smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webminlog wuftpd xinetd >> /etc/webmin/webmin.acl


# Edit the Webmin conf and make sure the port is set to 10000.
grep -Ev 'port' /etc/webmin/miniserv.conf > /etc/webmin/miniserv.conf.temp
mv -f /etc/webmin/miniserv.conf.temp /etc/webmin/miniserv.conf
echo "port=10000" >> /etc/webmin/miniserv.conf


# Make webmin automatically login to the MySQL module.
grep -Evi 'pass|login' /etc/webmin/mysql/config > /etc/webmin/mysql/config.temp
mv -f /etc/webmin/mysql/config.temp /etc/webmin/mysql/config


cat >> /etc/webmin/mysql/config <<EOF
pass=PASSWORD
login=root
backup_cmode_=0
backup_drop_=0
backup_before_=
backup_compress_=0
backup_single_=0
backup_compatible_=
backup_mkdir_=1
backup_=/opt/dbbackups
backup_charset_=
backup_tables_=
backup_options_=
backup_after_=
backup_where_=
EOF


cat >> /etc/webmin/config <<EOF
noremember=1
realname=
EOF


cat >> /etc/webmin/miniserv.conf <<EOF
pam_conv=
blockuser_time=
blocklock=
blockuser_failures=
no_pam=0
logouttime=15
utmp=1
EOF


/sbin/service webmin restart


echo "FINISH" | mail -s "${SUBJECT}" "${EMAIL}"

# QA Test
"${PROVISION_ROOT}"/qa.sh

/sbin/service sshd restart
