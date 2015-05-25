#OpenStack 手动安装手册（Juno）

##部署架构

为了更好的展现OpenStack各组件分布式部署的特点，以及逻辑网络配置的区别，本实验不采用All in One 的部署模式，而是采用多节点分开部署的方式，方便后续学习研究。

![architecture](/installation/images/architecture.png)

##网络拓扑

![networking](/installation/images/networking.png)

##环境准备

本实验采用Virtualbox Windows 版作为虚拟化平台，模拟相应的物理网络和物理服务器，如果需要部署到真实的物理环境，此步骤可以直接替换为在物理机上相应的配置，其原理相同。


Virtualbox 下载地址：https://www.virtualbox.org/wiki/Downloads

###虚拟网络

需要新建3个虚拟网络Net0、Net1和Net2，其在virtual box 中对应配置如下。

Network adapter type using "Intel PRO/1000 MT Desktop(82540EM)",otherwise network can not be detected by CentOS 7

	Net0:
		Network name: VirtualBox  host-only Ethernet Adapter#2
		Purpose: administrator / management network
		IP block: 10.20.0.0/24
		DHCP: disable
		Linux device: eth0

	Net1:
		Network name: VirtualBox  host-only Ethernet Adapter#3
		Purpose: public network
		DHCP: disable
		IP block: 172.16.0.0/24
		Linux device: eth1

	Net2：
		Network name: VirtualBox  host-only Ethernet Adapter#4
		Purpose: Storage/private network
		DHCP: disable
		IP block: 192.168.4.0/24
		Linux device: eth2

###虚拟机

需要新建3个虚拟机VM0、VM1和VM2，其对应配置如下。

	VM0：
		Name: controller0
		vCPU:1
		Memory :1G
		Disk:30G
		Networks: net1

	VM1：
		Name : network0
		vCPU:1
		Memory :1G
		Disk:30G
		Network:net1,net2,net3

	VM2：
		Name: compute0
		vCPU:2
		Memory :2G
		Disk:30G
		Networks:net1,net3

### 操作系统

ISO文件下载：http://mirrors.163.com/centos/7.1.1503/isos/x86_64/CentOS-7-x86_64-DVD-1503-01.iso

###网络设置

	controller0
	     eth0:10.20.0.10   (management network)
	     eth1:(disabled)
	     eth2:(disabled)

	network0
	     eth0:10.20.0.20    (management network)
	     eth1:172.16.0.20   (public/external network)
	     eth2:192.168.4.20  (private network)

	compute0
	     eth0:10.20.0.30   (management network)
	     eth1:(disabled)
	     eth2:192.168.4.30  (private network)

Note:CentOS 7 network interface name is like ifcfg-enp0sX instead of ifcfg-ethX.
how to using old version:
1. editing /etc/default/grub by adding the following content
net.ifnames=0 biosdevnames=0

GRUB_CMDLINE_LINUX="rd.lvm.lv=centos/root rd.lvm.lv=centos/swap rhgb quiet net.ifnames=0 biosdevnames=0"

2.re generating grub file
grub2-mkconfig -o /boot/grub2/grub.cfg

3. disable NetworkManager serivce
systemctl stop NetworkManager
systemctl disable NetworkManager

4.修改hosts 文件

	vi /etc/hosts

	127.0.0.1    localhost
	::1          localhost
	10.20.0.10   controller0
	10.20.0.20   network0
	10.20.0.30   compute0


5.禁用 selinux

	vi /etc/selinux/config
	SELINUX=disabled

6. 关闭防火墙
	systemctl stop firewalld.service
	systemctl disable firewalld.service

7. 安装NTP 服务

	yum install ntp -y

8. 安装repo

EPEL源: http://dl.fedoraproject.org/pub/epel/7/x86_64/

RDO源:  http://repos.fedorapeople.org/repos/openstack/openstack-juno/

	yum install -y yum-plugin-priorities
	yum install http://dl.fedoraproject.org/pub/epel/7/x86_64/e/epel-release-7-5.noarch.rpm
	yum install http://rdo.fedorapeople.org/openstack-juno/rdo-release-juno.rpm
	yum update -y

9 .安装openstack-utils,方便后续直接可以通过命令行方式修改配置文件

	yum install -y openstack-utils

10. reboot


##控制节点安装（controller0）
###基本服务安装与配置（controller0 node）
基本服务包括NTP 服务、MySQL数据库服务和AMQP服务，本实例采用MySQL 和RabbitMQ 作为这两个服务的实现。
1. modify hostname
   echo "controller0" > /etc/hostname

2.修改NTP配置文件，配置从127.127.1.0 时间同步。

	vi /etc/ntp.conf
	server 127.127.1.0

    重启ntp service

	systemctl restart ntpd.service



MySQL 服务安装

	yum install mariadb mariadb-server MySQL-python

修改MySQL配置

	vi /etc/my.cnf
	[mysqld]
	bind-address = 10.20.0.10
	default-storage-engine = innodb
	innodb_file_per_table
	collation-server = utf8_general_ci
	init-connect = 'SET NAMES utf8'
	character-set-server = utf8

启动MySQL服务

	systemctl enable mariadb.service
	systemctl start mariadb.service

交互式配置MySQL root 密码，设置密码为“openstack”

	mysql_secure_installation


RabbitMQ 安装消息服务，设置新的用户openstack/openstack

	yum install rabbitmq-server

	systemctl enable rabbitmq-server.service
	systemctl start rabbitmq-server.service

	rabbitmqctl add_user openstack openstack
	rabbitmqctl set_permissions -p / openstack ".*" ".*" ".*"

	[root@controller0 etc]# rabbitmqctl list_user_permissions openstack
	Listing permissions for user "openstack" ...
	/       .*      .*      .*
	...done.


配置修改后，重启rabbitmq后台服务

	systemctl enable rabbitmq-server.service
	systemctl start rabbitmq-server.service


网卡配置

	vi /etc/sysconfig/network-scripts/ifcfg-eth0

	DEVICE=eth0
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=10.20.0.10
	NETMASK=255.255.255.0


网络配置文件修改完后重启网络服务

	systemctl restart network


###Keyston 安装与配置

安装keystone 包

	yum install openstack-keystone python-keystoneclient -y

为keystone 设置admin 账户的 tokn


	ADMIN_TOKEN=$(openssl rand -hex 10)
	echo $ADMIN_TOKEN
	openstack-config --set /etc/keystone/keystone.conf DEFAULT admin_token $ADMIN_TOKEN


配置数据连接
	openstack-config --set /etc/keystone/keystone.conf database connection mysql://keystone:openstack@controller0/keystone

	openstack-config --set /etc/keystone/keystone.conf token provider keystone.toke.providers.uuid.Provider

	openstack-config --set /etc/keystone/keystone.conf token driver keystone.token.persistence.backends.sql.Token


	openstack-config --set /etc/keystone/keystone.conf revoke driver keystone.contrib.revoke.backends.sql.Revoke

	openstack-config --set /etc/keystone/keystone.conf DEFAULT debug True
	openstack-config --set /etc/keystone/keystone.conf DEFAULT verbose True

设置Keystone 用 PKI tokens


	keystone-manage pki_setup --keystone-user keystone --keystone-group keystone
	chown -R keystone:keystone /etc/keystone/ssl
	chmod -R o-rwx /etc/keystone/ssl


为Keystone 建表

	mysql -uroot -popenstack -e "CREATE DATABASE keystone;"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'controller0' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY 'openstack';"

初始化Keystone数据库

	su -s /bin/sh -c "keystone-manage db_sync"

启动keystone 服务

	systemctl enable openstack-keystone.service
	systemctl start openstack-keystone.service


	(crontab -l -u keystone 2>&1 | grep -q token_flush) || \
  echo '@hourly /usr/bin/keystone-manage token_flush >/var/log/keystone/keystone-tokenflush.log 2>&1' \
  >> /var/spool/cron/keystone

设置认证信息

	export OS_SERVICE_TOKEN=`echo $ADMIN_TOKEN`
	export OS_SERVICE_ENDPOINT=http://controller0:35357/v2.0


创建管理员和系统服务使用的租户

	keystone tenant-create --name=admin --description="Admin Tenant"
	keystone tenant-create --name=service --description="Service Tenant"


创建管理员用户

	keystone user-create --name=admin --pass=admin --email=admin@example.com

创建管理员角色


	keystone role-create --name=admin


为管理员用户分配"管理员"角色


	keystone user-role-add --user=admin --tenant=admin --role=admin


为keystone 服务建立 endpoints


	keystone service-create --name=keystone --type=identity --description="Keystone Identity Service"


为keystone 建立 servie 和 endpoint 关联


	keystone endpoint-create \
	--service-id=$(keystone service-list | awk '/ identity / {print $2}') \
	--publicurl=http://controller0:5000/v2.0 \
	--internalurl=http://controller0:5000/v2.0 \
	--adminurl=http://controller0:35357/v2.0


验证keystone 安装的正确性

取消先前的Token变量，不然会干扰新建用户的验证。

	unset OS_SERVICE_TOKEN OS_SERVICE_ENDPOINT

先用命令行方式验证

	keystone --os-username=admin --os-password=admin --os-auth-url=http://controller0:35357/v2.0 token-get
	keystone --os-username=admin --os-password=admin --os-tenant-name=admin --os-auth-url=http://controller0:35357/v2.0 token-get


让后用设置环境变量认证,保存认证信息

	vi ~/admin-openrc.sh

	export OS_USERNAME=admin
	export OS_PASSWORD=admin
	export OS_TENANT_NAME=admin
	export OS_AUTH_URL=http://controller0:35357/v2.0


source 该文件使其生效

	source admin-openrc.sh
	keystone token-get


Keystone 安装结束。

###Glance 安装与配置

安装Glance 的包

	yum install openstack-glance python-glanceclient -y

初始化Glance数据库
	mysql -uroot -popenstack -e "CREATE DATABASE glance;"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON keystone.* TO 'glance'@'controller0' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%' IDENTIFIED BY 'openstack';"

创建glance 用户


	keystone user-create --name=glance --pass=glance --email=glance@example.com


并分配service角色

	keystone user-role-add --user=glance --tenant=service --role=admin

创建glance 服务

	keystone service-create --name=glance --type=image --description="Glance Image Service"


创建keystone 的endpoint

	keystone endpoint-create \
	--service-id=$(keystone service-list | awk '/ image / {print $2}')  \
	--publicurl=http://controller0:9292 \
	--internalurl=http://controller0:9292 \
	--adminurl=http://controller0:9292


用openstack util 修改glance api 和 register 配置文件

	openstack-config --set /etc/glance/glance-api.conf database connection mysql://glance:openstack@controller0/glance

	openstack-config --set /etc/glance/glance-api.conf DEFAULT debug True
	openstack-config --set /etc/glance/glance-api.conf DEFAULT verbose True
	openstack-config --set /etc/glance/glance-api.conf DEFAULT notification_driver noop
	openstack-config --set /etc/glance/glance-api.conf keystone_authtoken auth_uri http://controller0:5000/v2.0
	openstack-config --set /etc/glance/glance-api.conf keystone_authtoken identity_uri http://controller0:35357
	openstack-config --set /etc/glance/glance-api.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/glance/glance-api.conf keystone_authtoken admin_user glance
	openstack-config --set /etc/glance/glance-api.conf keystone_authtoken admin_password glance

	openstack-config --set /etc/glance/glance-api.conf glance_store default_store file
	openstack-config --set /etc/glance/glance-api.conf paste_deploy flavor keystone


	openstack-config --set /etc/glance/glance-registry.conf database connection mysql://glance:openstack@controller0/glance
	openstack-config --set /etc/glance/glance-registry.conf DEFAULT debug True
	openstack-config --set /etc/glance/glance-registry.conf DEFAULT verbose True
	openstack-config --set /etc/glance/glance-registry.conf keystone_authtoken auth_uri http://controller0:5000/v2.0
	openstack-config --set /etc/glance/glance-registry.conf keystone_authtoken identity_uri http://controller0:35357
	openstack-config --set /etc/glance/glance-registry.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/glance/glance-registry.conf keystone_authtoken admin_user glance
	openstack-config --set /etc/glance/glance-registry.conf keystone_authtoken admin_password glance
	openstack-config --set /etc/glance/glance-registry.conf paste_deploy flavor keystone

Populate the Image Service database:
	su -s /bin/sh -c "glance-manage db_sync" glance

启动glance 相关的两个服务

	systemctl enable openstack-glance-api.service openstack-glance-registry.service
	systemctl start openstack-glance-api.service openstack-glance-registry.service


下载最Cirros镜像验证glance 安装是否成功

	wget http://download.cirros-cloud.net/0.3.3/cirros-0.3.3-x86_64-disk.img
	glance image-create --progress --name="CirrOS 0.3.3" --disk-format=qcow2  --container-format=bare --is-public=true < cirros-0.3.3-x86_64-disk.img


查看刚刚上传的image

	glance  image-list

如果显示相应的image 信息说明安装成功。


###Nova 安装与配置

	yum install -y openstack-nova-api openstack-nova-cert openstack-nova-conductor \
	openstack-nova-console openstack-nova-novncproxy openstack-nova-scheduler python-novaclient

在keystone中创建nova相应的用户和服务

	keystone user-create --name=nova --pass=nova --email=nova@example.com
	keystone user-role-add --user=nova --tenant=service --role=admin

keystone 注册服务

	keystone service-create --name=nova --type=compute --description="Nova Compute Service"

keystone 注册endpoint

	keystone endpoint-create \
	--service-id=$(keystone service-list | awk '/ compute / {print $2}')  \
	--publicurl=http://controller0:8774/v2/%\(tenant_id\)s \
	--internalurl=http://controller0:8774/v2/%\(tenant_id\)s \
	--adminurl=http://controller0:8774/v2/%\(tenant_id\)s


创建数据库

	mysql -uroot -popenstack -e "CREATE DATABASE nova;"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'controller0' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' IDENTIFIED BY 'openstack';"

配置nova.conf
	openstack-config --set /etc/nova/nova.conf database connection mysql://nova:openstack@controller0/nova

	openstack-config --set /etc/nova/nova.conf DEFAULT debug True
	openstack-config --set /etc/nova/nova.conf DEFAULT verbose True
	openstack-config --set /etc/nova/nova.conf DEFAULT rpc_backend rabbit
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_host controller0
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_userid openstack
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_password  openstack

	openstack-config --set /etc/nova/nova.conf DEFAULT my_ip 10.20.0.10
	openstack-config --set /etc/nova/nova.conf DEFAULT vncserver_listen 10.20.0.10
	openstack-config --set /etc/nova/nova.conf DEFAULT vncserver_proxyclient_address 10.20.0.10
	openstack-config --set /etc/nova/nova.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/nova/nova.conf keystone_authtoken auth_uri  http://controller0:5000/v2.0
	openstack-config --set /etc/nova/nova.conf keystone_authtoken identity_uri  http://controller0:35357

	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_user nova
	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_password nova

	openstack-config --set /etc/nova/nova.conf glance host controller0

初始化数据库
	su -s /bin/sh -c "nova-manage db sync" nova

启动服务

  systemctl start openstack-nova-api.service openstack-nova-cert.service \
  openstack-nova-consoleauth.service openstack-nova-scheduler.service \
  openstack-nova-conductor.service openstack-nova-novncproxy.service

添加到系统服务

  systemctl enable openstack-nova-api.service openstack-nova-cert.service \
  openstack-nova-consoleauth.service openstack-nova-scheduler.service \
  openstack-nova-conductor.service openstack-nova-novncproxy.service


检查服务是否正常

	nova-manage service list

	root@controller0 ~]# nova-manage service list
	Binary           Host                                 Zone             Status     State Updated_At
	nova-consoleauth controller0                          internal         enabled    :-)   2013-11-12 11:14:56
	nova-cert        controller0                          internal         enabled    :-)   2013-11-12 11:14:56
	nova-scheduler   controller0                          internal         enabled    :-)   2013-11-12 11:14:56
	nova-conductor   controller0                          internal         enabled    :-)   2013-11-12 11:14:56

检查进程

	[root@controller0 ~]# ps -ef|grep nova
	nova      7240     1  1 23:11 ?        00:00:02 /usr/bin/python /usr/bin/nova-api --logfile /var/log/nova/api.log
	nova      7252     1  1 23:11 ?        00:00:01 /usr/bin/python /usr/bin/nova-cert --logfile /var/log/nova/cert.log
	nova      7264     1  1 23:11 ?        00:00:01 /usr/bin/python /usr/bin/nova-consoleauth --logfile /var/log/nova/consoleauth.log
	nova      7276     1  1 23:11 ?        00:00:01 /usr/bin/python /usr/bin/nova-scheduler --logfile /var/log/nova/scheduler.log
	nova      7288     1  1 23:11 ?        00:00:01 /usr/bin/python /usr/bin/nova-conductor --logfile /var/log/nova/conductor.log
	nova      7300     1  0 23:11 ?        00:00:00 /usr/bin/python /usr/bin/nova-novncproxy --web /usr/share/novnc/
	nova      7336  7240  0 23:11 ?        00:00:00 /usr/bin/python /usr/bin/nova-api --logfile /var/log/nova/api.log
	nova      7351  7240  0 23:11 ?        00:00:00 /usr/bin/python /usr/bin/nova-api --logfile /var/log/nova/api.log
	nova      7352  7240  0 23:11 ?        00:00:00 /usr/bin/python /usr/bin/nova-api --logfile /var/log/nova/api.log


###Neutron server安装与配置

安装Neutron server 相关包

	yum install -y openstack-neutron openstack-neutron-ml2 python-neutronclient

在keystone中创建 Neutron 相应的用户和服务

	keystone user-create --name neutron --pass neutron --email neutron@example.com

	keystone user-role-add --user neutron --tenant service --role admin

	keystone service-create --name neutron --type network --description "OpenStack Networking"

	keystone endpoint-create \
	--service-id $(keystone service-list | awk '/ network / {print $2}') \
	--publicurl http://controller0:9696 \
	--adminurl http://controller0:9696 \
	--internalurl http://controller0:9696

为Neutron 在MySQL建数据库

	mysql -uroot -popenstack -e "CREATE DATABASE neutron;"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'localhost' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'%' IDENTIFIED BY 'openstack';"
	mysql -uroot -popenstack -e "GRANT ALL PRIVILEGES ON neutron.* TO 'neutron'@'controller0' IDENTIFIED BY 'openstack';"

配置MySQL

	openstack-config --set /etc/neutron/neutron.conf database connection mysql://neutron:openstack@controller0/neutron

配置rabbitmq

	openstack-config --set /etc/neutron/neutron.conf DEFAULT rpc_backend rabbit
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_host controller0
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_userid openstack
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_password  openstack

配置Neutron Keystone 认证

	openstack-config --set /etc/neutron/neutron.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_uri http://controller0:5000/v2.0
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken identity_uri http://controller0:35357
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_user neutron
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_password neutron


	openstack-config --set /etc/neutron/neutron.conf DEFAULT core_plugin ml2
	openstack-config --set /etc/neutron/neutron.conf DEFAULT service_plugins router
	openstack-config --set /etc/neutron/neutron.conf DEFAULT allow_overlapping_ips True

	openstack-config --set /etc/neutron/neutron.conf DEFAULT notify_nova_on_port_status_changes True
	openstack-config --set /etc/neutron/neutron.conf DEFAULT notify_nova_on_port_data_changes True
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_url http://controller0:8774/v2
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_region_name  regionOne
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_admin_username nova
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_admin_tenant_id $(keystone tenant-list | awk '/ service / { print $2 }')
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_admin_password nova
	openstack-config --set /etc/neutron/neutron.conf DEFAULT nova_admin_auth_url http://controller0:35357/v2.0

配置Neutron ml2 plugin 用openvswitch

	ln -s /etc/neutron/plugins/ml2/ml2_conf.ini /etc/neutron/plugin.ini

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 type_drivers flat,gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 tenant_network_types gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 mechanism_drivers openvswitch

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2_type_gre tunnel_id_ranges 1:1000

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup firewall_driver neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_security_group True
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_ipset True

配置nova 使用Neutron 作为network 服务

	openstack-config --set /etc/nova/nova.conf DEFAULT network_api_class nova.network.neutronv2.api.API
	openstack-config --set /etc/nova/nova.conf DEFAULT linuxnet_interface_driver nova.network.linux_net.LinuxOVSInterfaceDriver
	openstack-config --set /etc/nova/nova.conf DEFAULT security_group_api neutron
	openstack-config --set /etc/nova/nova.conf DEFAULT firewall_driver nova.virt.firewall.NoopFirewallDriver

	openstack-config --set /etc/nova/nova.conf neutron url http://controller0:9696
	openstack-config --set /etc/nova/nova.conf neutron auth_strategy keystone
	openstack-config --set /etc/nova/nova.conf neutron admin_tenant_name service
	openstack-config --set /etc/nova/nova.conf neutron admin_username neutron
	openstack-config --set /etc/nova/nova.conf neutron admin_password neutron
	openstack-config --set /etc/nova/nova.conf neutron admin_auth_url http://controller0:35357/v2.0
	openstack-config --set /etc/nova/nova.conf neutron service_metadata_proxy True
	openstack-config --set /etc/nova/nova.conf neutron metadata_proxy_shared_secret openstack

Populate the database
su -s /bin/sh -c "neutron-db-manage --config-file /etc/neutron/neutron.conf \
  --config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade juno" neutron

重启nova controller 上的服务

	systemctl restart openstack-nova-api.service openstack-nova-scheduler.service \
  openstack-nova-conductor.service

启动Neutron server

	service neutron-server start
	chkconfig neutron-server on

##网路节点安装（network0 node）


主机名设置

1. modify hostname
   echo "network0" > /etc/hostname

修改NTP配置文件，controller0同步本地，其他node配置从controller0时间同步


	vi /etc/ntp.conf

	server 10.20.0.10 iburst



立即同步并检查时间同步配置是否正确。(除了controller0以外)

	ntpdate -u 10.20.0.10
	[prefered]
	systemctl enable ntpd.service
	systemctl start ntpd.service
	ntpq -p



网卡配置

	vi /etc/sysconfig/network-scripts/ifcfg-eth0
	DEVICE=eth0
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=10.20.0.20
	NETMASK=255.255.255.0

	vi /etc/sysconfig/network-scripts/ifcfg-eth1
	DEVICE=eth1
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=172.16.0.20
	NETMASK=255.255.255.0

	vi /etc/sysconfig/network-scripts/ifcfg-eth2
	DEVICE=eth2
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=192.168.4.20
	NETMASK=255.255.255.0

网络配置文件修改完后重启网络服务

	serice network restart

先安装Neutron 相关的包

	yum install -y openstack-neutron openstack-neutron-ml2 openstack-neutron-openvswitch

允许ip forward

	vi /etc/sysctl.conf
	net.ipv4.ip_forward=1
	net.ipv4.conf.all.rp_filter=0
	net.ipv4.conf.default.rp_filter=0

立即生效

	sysctl -p

配置rabbit

	openstack-config --set /etc/neutron/neutron.conf DEFAULT rpc_backend rabbit
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_host controller0
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_userid openstack
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_password  openstack


配置Neutron keysone 认证

	openstack-config --set /etc/neutron/neutron.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_uri http://controller0:5000/v2.0
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken identity_uri http://controller0:35357
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_user neutron
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_password neutron

enable the Modular Layer 2 (ML2) plug-in, router service, and overlapping IP addresses

	openstack-config --set /etc/neutron/neutron.conf DEFAULT core_plugin ml2
	openstack-config --set /etc/neutron/neutron.conf DEFAULT service_plugins router
	openstack-config --set /etc/neutron/neutron.conf DEFAULT allow_overlapping_ips True

配置Neutron 使用ml + openvswitch +gre

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 type_drivers flat,gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 tenant_network_types gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 mechanism_drivers openvswitch
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2_type_flat flat_networks external
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2_type_gre tunnel_id_ranges 1:1000
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup firewall_driver neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_security_group True
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_ipset True

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ovs local_ip 192.168.4.20
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ovs enable_tunneling True
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ovs bridge_mappings external:br-ex

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini agent tunnel_types gre


	ln -s /etc/neutron/plugins/ml2/ml2_conf.ini /etc/neutron/plugin.ini
	cp /etc/init.d/neutron-openvswitch-agent /etc/init.d/neutronopenvswitch-agent.orig
	sed -i 's,plugins/openvswitch/ovs_neutron_plugin.ini,plugin.ini,g' /etc/init.d/neutron-openvswitch-agent

配置l3

	openstack-config --set /etc/neutron/l3_agent.ini DEFAULT interface_driver neutron.agent.linux.interface.OVSInterfaceDriver
	openstack-config --set /etc/neutron/l3_agent.ini DEFAULT use_namespaces True
	openstack-config --set /etc/neutron/l3_agent.ini DEFAULT router_delete_namespaces True
	openstack-config --set /etc/neutron/l3_agent.ini DEFAULT external_network_bridge br-ex

配置dhcp agent
	1.creating new file and add the following content
	dhcp-option-force=26,1454

	2.
	openstack-config --set /etc/neutron/dhcp_agent.ini DEFAULT interface_driver neutron.agent.linux.interface.OVSInterfaceDriver
	openstack-config --set /etc/neutron/dhcp_agent.ini DEFAULT dhcp_driver neutron.agent.linux.dhcp.Dnsmasq
	openstack-config --set /etc/neutron/dhcp_agent.ini DEFAULT use_namespaces True
	openstack-config --set /etc/neutron/dhcp_agent.ini DEFAULT router_delete_namespaces True
	openstack-config --set /etc/neutron/dhcp_agent.ini DEFAULT dnsmasq_config_file /etc/neutron/dnsmasq-neutron.conf

    3. pkill dnsmasq



配置metadata agent

	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT auth_url http://controller0:5000/v2.0
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT auth_region regionOne
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT admin_tenant_name service
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT admin_user neutron
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT admin_password neutron
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT nova_metadata_ip controller0
	openstack-config --set /etc/neutron/metadata_agent.ini DEFAULT metadata_proxy_shared_secret openstack

	service openvswitch start
	chkconfig openvswitch on

	ovs-vsctl add-br br-int
	ovs-vsctl add-br br-ex
	ovs-vsctl add-port br-ex eth1

修改eth1和br-ext 网络配置

	vi /etc/sysconfig/network-scripts/ifcfg-eth1
	DEVICE=eth1
	ONBOOT=yes
	BOOTPROTO=none
	PROMISC=yes

	vi /etc/sysconfig/network-scripts/ifcfg-br-ex

	DEVICE=br-ex
	TYPE=Bridge
	ONBOOT=no
	BOOTPROTO=none

重启网络服务

	service network restart

为br-ext 添加ip

	ip link set br-ex up
	sudo ip addr add 172.16.0.20/24 dev br-ex

启动Neutron 服务

	systemctl enable neutron-openvswitch-agent.service neutron-l3-agent.service \
  neutron-dhcp-agent.service neutron-metadata-agent.service \
  neutron-ovs-cleanup.service

	systemctl start neutron-openvswitch-agent.service neutron-l3-agent.service \
  neutron-dhcp-agent.service neutron-metadata-agent.service

verify
	[root@controller0 ~]# neutron agent-list
+--------------------------------------+--------------------+----------+-------+----------------+---------------------------+
| id                                   | agent_type         | host     | alive | admin_state_up | binary                    |
+--------------------------------------+--------------------+----------+-------+----------------+---------------------------+
| 0c4db9b0-2269-449d-ae65-5f9ab1b771a7 | Open vSwitch agent | network0 | :-)   | True           | neutron-openvswitch-agent |
| a205f22d-5b9a-4e7b-bf3d-ad13ecf88342 | Metadata agent     | network0 | :-)   | True           | neutron-metadata-agent    |
| a768b742-2295-42ad-ba72-e42739a80328 | L3 agent           | network0 | :-)   | True           | neutron-l3-agent          |
| bc4e2cf8-0858-4bec-994f-478ca22b0f6e | DHCP agent         | network0 | :-)   | True           | neutron-dhcp-agent        |
+--------------------------------------+--------------------+----------+-------+----------------+---------------------------+


## 计算节点安装（（compute0 node）
1. modify hostname
   echo "compute0" > /etc/hostname

2.修改NTP配置文件，配置从127.127.1.0 时间同步。

	vi /etc/ntp.conf
	server 10.20.0.10 iburst
   重启ntp service

	service ntpd restart

3. 网卡配置

	vi /etc/sysconfig/network-scripts/ifcfg-eth0
	DEVICE=eth0
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=10.20.0.30
	NETMASK=255.255.255.0

	vi /etc/sysconfig/network-scripts/ifcfg-eth2
	DEVICE=eth2
	TYPE=Ethernet
	ONBOOT=yes
	NM_CONTROLLED=yes
	BOOTPROTO=static
	IPADDR=192.168.4.30
	NETMASK=255.255.255.0

内核参数修改
Edit the /etc/sysctl.conf
	net.ipv4.conf.all.rp_filter=0
	net.ipv4.conf.default.rp_filter=0

	sysctl -p

网络配置文件修改完后重启网络服务

	systemctl restart network

安装nova 相关包

	yum install openstack-nova-compute sysfsutils

配置nova

	openstack-config --set /etc/nova/nova.conf DEFAULT debug False
	openstack-config --set /etc/nova/nova.conf DEFAULT verbose False
	openstack-config --set /etc/nova/nova.conf DEFAULT rpc_backend rabbit
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_host controller0
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_userid openstack
	openstack-config --set /etc/nova/nova.conf DEFAULT rabbit_password  openstack
	openstack-config --set /etc/nova/nova.conf DEFAULT my_ip 10.20.0.30
	openstack-config --set /etc/nova/nova.conf DEFAULT vnc_enabled True
	openstack-config --set /etc/nova/nova.conf DEFAULT vncserver_listen 0.0.0.0
	openstack-config --set /etc/nova/nova.conf DEFAULT vncserver_proxyclient_address 10.20.0.10
	openstack-config --set /etc/nova/nova.conf DEFAULT novncproxy_base_url http://controller0:6080/vnc_auto.html
	openstack-config --set /etc/nova/nova.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/nova/nova.conf keystone_authtoken auth_uri  http://controller0:5000/v2.0
	openstack-config --set /etc/nova/nova.conf keystone_authtoken identity_uri  http://controller0:35357
	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_user nova
	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/nova/nova.conf keystone_authtoken admin_password nova
	openstack-config --set /etc/nova/nova.conf glance host controller0
	openstack-config --set /etc/nova/nova.conf libvirt virt_type qemu

启动compute 节点服务

	systemctl start libvirtd.service openstack-nova-compute.service
	systemctl enable libvirtd.service openstack-nova-compute.service

在controller 节点检查compute服务是否启动

	nova-manage service list

多出计算节点服务

	[root@controller0 ~]# nova-manage service list
	Binary           Host                                 Zone             Status     State Updated_At
	nova-consoleauth controller0                          internal         enabled    :-)   2014-07-19 09:04:18
	nova-cert        controller0                          internal         enabled    :-)   2014-07-19 09:04:19
	nova-conductor   controller0                          internal         enabled    :-)   2014-07-19 09:04:20
	nova-scheduler   controller0                          internal         enabled    :-)   2014-07-19 09:04:20
	nova-compute     compute0                             nova             enabled    :-)   2014-07-19 09:04:19

安装neutron ml2 和openvswitch agent

	yum install openstack-neutron-ml2 openstack-neutron-openvswitch


配置Neutron Keystone 认证

	openstack-config --set /etc/neutron/neutron.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_uri http://controller0:5000
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_host controller0
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_protocol http
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_port 35357
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_user neutron
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_password neutron


配置rabbit

	openstack-config --set /etc/neutron/neutron.conf DEFAULT rpc_backend rabbit
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_host controller0
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_userid openstack
	openstack-config --set /etc/neutron/neutron.conf DEFAULT rabbit_password  openstack


配置Neutron keysone 认证

	openstack-config --set /etc/neutron/neutron.conf DEFAULT auth_strategy keystone
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken auth_uri http://controller0:5000/v2.0
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken identity_uri http://controller0:35357
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_tenant_name service
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_user neutron
	openstack-config --set /etc/neutron/neutron.conf keystone_authtoken admin_password neutron

enable the Modular Layer 2 (ML2) plug-in, router service, and overlapping IP addresses

	openstack-config --set /etc/neutron/neutron.conf DEFAULT core_plugin ml2
	openstack-config --set /etc/neutron/neutron.conf DEFAULT service_plugins router
	openstack-config --set /etc/neutron/neutron.conf DEFAULT allow_overlapping_ips True

配置Neutron 使用ml + openvswitch +gre

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 type_drivers flat,gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 tenant_network_types gre
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2 mechanism_drivers openvswitch
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ml2_type_gre tunnel_id_ranges 1:1000
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup firewall_driver neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_security_group True
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini securitygroup enable_ipset True

	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ovs local_ip 192.168.4.30
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini ovs enable_tunneling True
	openstack-config --set /etc/neutron/plugins/ml2/ml2_conf.ini agent tunnel_types gre


	ln -s /etc/neutron/plugins/ml2/ml2_conf.ini /etc/neutron/plugin.ini
	cp /usr/lib/systemd/system/neutron-openvswitch-agent.service \
  /usr/lib/systemd/system/neutron-openvswitch-agent.service.orig
  sed -i 's,plugins/openvswitch/ovs_neutron_plugin.ini,plugin.ini,g' \
  /usr/lib/systemd/system/neutron-openvswitch-agent.service


配置 Nova 使用Neutron 提供网络服务

	openstack-config --set /etc/nova/nova.conf DEFAULT network_api_class nova.network.neutronv2.api.API
	openstack-config --set /etc/nova/nova.conf DEFAULT linuxnet_interface_driver nova.network.linux_net.LinuxOVSInterfaceDriver
	openstack-config --set /etc/nova/nova.conf DEFAULT security_group_api neutron
	openstack-config --set /etc/nova/nova.conf DEFAULT firewall_driver nova.virt.firewall.NoopFirewallDriver

	openstack-config --set /etc/nova/nova.conf neutron url http://controller0:9696
	openstack-config --set /etc/nova/nova.conf neutron auth_strategy keystone
	openstack-config --set /etc/nova/nova.conf neutron admin_tenant_name service
	openstack-config --set /etc/nova/nova.conf neutron admin_username neutron
	openstack-config --set /etc/nova/nova.conf neutron admin_password neutron
	openstack-config --set /etc/nova/nova.conf neutron admin_auth_url http://controller0:35357/v2.0


	systemctl restart openstack-nova-compute.service

	systemctl enable openvswitch.service
	systemctl start openvswitch.service

	systemctl enable neutron-openvswitch-agent.service
	systemctl start neutron-openvswitch-agent.service


检查agent 是否启动正常

	neutron agent-list

启动正常显示

	[root@controller0 ~]# neutron agent-list
	+--------------------------------------+--------------------+----------+-------+----------------+
	| id                                   | agent_type         | host     | alive | admin_state_up |
	+--------------------------------------+--------------------+----------+-------+----------------+
	| 2c5318db-6bc2-4d09-b728-bbdd677b1e72 | L3 agent           | network0 | :-)   | True           |
	| 4a79ff75-6205-46d0-aec1-37f55a8d87ce | Open vSwitch agent | network0 | :-)   | True           |
	| 5a5bd885-4173-4515-98d1-0edc0fdbf556 | Open vSwitch agent | compute0 | :-)   | True           |
	| 5c9218ce-0ebd-494a-b897-5e2df0763837 | DHCP agent         | network0 | :-)   | True           |
	| 76f2069f-ba84-4c36-bfc0-3c129d49cbb1 | Metadata agent     | network0 | :-)   | True           |
	+--------------------------------------+--------------------+----------+-------+----------------+

##创建初始网络

创建外部网络

	neutron net-create ext-net --router:external True \
  --provider:physical_network external --provider:network_type flat

为外部网络添加subnet

	neutron subnet-create ext-net --name ext-subnet \
	--allocation-pool start=172.16.0.100,end=172.16.0.200 \
	--disable-dhcp --gateway 172.16.0.1 172.16.0.0/24

创建租户网络

首先创建demo用户、租户已经分配角色关系

	keystone user-create --name=demo --pass=demo --email=demo@example.com
	keystone tenant-create --name=demo --description="Demo Tenant"
	keystone user-role-add --user=demo --role=_member_ --tenant=demo

创建租户网络demo-net

	neutron net-create demo-net

为租户网络添加subnet

	neutron subnet-create demo-net --name demo-subnet --gateway 192.168.1.1 192.168.1.0/24


为租户网络创建路由，并连接到外部网络

	neutron router-create demo-router

将demo-net 连接到路由器

	neutron router-interface-add demo-router demo-subnet

设置demo-router 默认网关

	neutron router-gateway-set demo-router ext-net


启动一个instance

nova boot --flavor m1.tiny --image $(nova image-list|awk '/ CirrOS / { print $2 }') --nic net-id=$(neutron net-list|awk '/ demo-net / { print $2 }') --security-group default demo-instance1

[ejifeli]
The default security group has no entries for ICMP and SSH traffic
http://help.switch.ch/engines/faq/why-cant-i-ping-my-virtual-machine-or-ssh-into-it/

neutron security-group-rule-list

nova secgroup-add-rule default icmp -1 -1 0.0.0.0/0
nova secgroup-add-rule default tcp 22 22 0.0.0.0/0

#neutron floatingip-create ext-net
#nova floating-ip-associate demo-instance1 172.10.0.xxx


[ejifeli]




##Dashboard 安装

安装Dashboard 相关包

	yum install openstack-dashboard httpd mod_wsgi memcached pythonmemcached

配置mencached

	vi /etc/openstack-dashboard/local_settings

	CACHES = {
	'default': {
	'BACKEND' : 'django.core.cache.backends.memcached.MemcachedCache',
	'LOCATION' : '127.0.0.1:11211'
	}
	}

配置Keystone hostname

	vi /etc/openstack-dashboard/local_settings
	OPENSTACK_HOST = "controller0"

fix package bug

	chown -R apache:apache /usr/share/openstack-dashboard/static

启动Dashboard 相关服务

	chown -R apache:apache /usr/share/openstack-dashboard/static

启动服务
	systemctl enable httpd.service memcached.service
	systemctl start httpd.service memcached.service


打开浏览器验证,用户名：admin 密码：admin

	http://10.20.0.10/dashboard

