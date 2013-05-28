echo -e "###################\nQA Checklist\n###################\n\n" > QA.log

echo -e "\n\n\n#############################\nServer OS\n#############################\n\n" >> QA.log
cat /etc/*-release >> QA.log

echo -e "\n\n\n#############################\nSwap Info\n#############################\n\n" >> QA.log
echo Swap Size in KB >> QA.log
free | grep -i swap | awk {'print $2'} >> QA.log

echo -e "\n\n\n#############################\nMySQL Version\n#############################\n\n" >> QA.log
/usr/bin/mysqladmin -uroot -pPASSWORD --version >> QA.log

echo -e "\n\n\n#############################\nMySQL Service Status\n#############################\n\n" >> QA.log
/sbin/service mysqld status >> QA.log

echo -e "\n\n\n#############################\nMySQL Run Level\n#############################\n\n" >> QA.log
chkconfig --list | grep -i "mysql" >> QA.log

echo -e "\n\n\n#############################\nTomcat Version\n#############################\n\n" >> QA.log
/opt/tomcat/bin/version.sh >> QA.log

echo -e "\n\n\n#############################\nTomcat Service Status\n#############################\n\n" >> QA.log
/sbin/service tomcat status >> QA.log

echo -e "\n\n\n#############################\nTomcat Run Level\n#############################\n\n" >> QA.log
chkconfig --list | grep -i "tomcat" >> QA.log

echo -e "\n\n\n#############################\nPostfix Service Status\n#############################\n\n" >> QA.log
/sbin/service postfix status >> QA.log

echo -e "\n\n\n#############################\nPostfix Run Level\n#############################\n\n" >> QA.log
chkconfig --list | grep -i "postfix" >> QA.log

echo -e "\n\n\n#############################\nWebmin Service Status\n#############################\n\n" >> QA.log
/sbin/service webmin status >> QA.log

echo -e "\n\n\n#############################\nMySQL Backups\n#############################\n\n" >> QA.log
ls -lsah /opt/dbbackups >> QA.log

echo -e "\n\n\n#############################\niptables rules\n#############################\n\n" >> QA.log
/sbin/iptables -t nat -L -n >> QA.log

echo -e "\n\n\n#############################\ncrontab\n#############################\n\n" >> QA.log
crontab -l >> QA.log
# E-mail results to me
mail -s "$(hostname) QA Log" jbarnett@company.com < QA.log
