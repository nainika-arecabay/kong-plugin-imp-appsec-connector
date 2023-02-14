Install kong on ubuntu:

1. Download the Kong package:
    
    	sudo apt-get update
	sudo apt-get install openssl libpcre3 procps perl
	
	curl -Lo kong-enterprise-edition-3.1.1.3.all.deb "https://download.konghq.com/gateway-3.x-ubuntu-$(lsb_release -sc)/pool/all/k/kong-enterprise-   edition/kong-enterprise-edition_3.1.1.3_amd64.deb"


2. Install the package:
	
    	sudo apt-get install zlib1g-dev
    	sudo dpkg -i kong-enterprise-edition-3.1.1.3.all.deb
  
  
3. Install and setup postgress db:

    	sudo apt-get install postgresql postgresql-contrib
    	sudo -i -u postgres
    
   	Type psql to access a postgress prompt and \q  to exit the prompt
    
    	CREATE USER kong; CREATE DATABASE kong OWNER kong;
    	ALTER USER kong WITH PASSWORD 'password you set';


4. Setup kong configuration:

    	sudo cp /etc/kong/kong.conf.default /etc/kong/kong.conf

    	$ sudo vim /etc/kong/kong.conf
    	and paste the below lines
    	pg_user = kong
    	pg_password = password you set
    	pg_database = kong


5. Set up the db using the migrations cmd and then start the kong

  		sudo kong migrations bootstrap
		sudo kong migrations up -c /etc/kong/kong.conf
		sudo kong start -c /etc/kong/kong.conf


Steps to setup service, route and custom plugin 


1. Install the imp-appsec-connector Kong plugin on each node in your Kong cluster via luarocks. As this plugin source is already hosted in Luarocks.org, please run the below command:

		luarocks install imp-appsec-connector


2. Add to the custom_plugins list in your Kong configuration (on each Kong node):
	
		Path - /etc/kong/kong.conf
		custom_plugins = imp-appsec-connector

3. Cmd to generate Service:

		curl -i -X POST   --url http://localhost:8001/services/   --data 'name=bankapp'   --data 'url=http://myretailbank.impvdemo.com/'

4. Cmd to generate route:

		curl -i -X POST --url http://localhost:8001/services/bankapp/routes/ --data 'name=bankapp' --data paths\[\]=/ --data 'hosts[]=54.176.196.168'

5. Plugin configuration cmd to enable on service:

		curl -X POST http://localhost:8001/services/bankapp/plugins --data 'config.destination_addr=54.226.92.142' --data 'config.connection_type=tcp' --data 'config.destination_port=8080' --data 'name=imp-appsec-connector'

