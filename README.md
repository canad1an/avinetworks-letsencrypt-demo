# Avi Networks

This playbook is designed to create a new gslbservice and virtualservice on an Avi controller and generate a new valid certificate through Lets Encrypt.

## Variables
/vars/creds.yaml - Login credentials for the Avi Controller

```
avi_controller_username: admin
avi_controller_password: avi123
avi_api_version: 20.1.3
avi_controller_ford: 5.5.5.5
aws_subnet: aws-subnet
```

Example extra variables:
```
ApplicationName=testapp1.company.com
ApplicationType=https_termination [http|https_proxy|https_termination|tcp]
Tenant=admin
HealthMonitor=ping
ListeningPort='443'
sni=none [parent|child]
PoolMembers='10.10.10.10,80,enabled'
CloudName=Default-Cloud
ssl_key=ssl/key.key
ssl_crt=ssl/crt.crt
GenerateCertificate=True
```

## Usage
It is recommended that you always use an encrypted vault. The creds.yaml file needs to be encrypted.

Example to create the virtualservice and gslbservice using existing cert and key:
```
ansible-playbook main.yaml --vault-password-file=../vault_pass --extra-vars "ApplicationName=testapp1.company.com ApplicationType=https_termination Tenant=admin HealthMonitor=ping ListeningPort='443' sni=none PoolMembers='10.1.1.1,80,enabled' ssl_key=ssl/key.key ssl_crt=ssl/crt.crt CloudName=Default-Cloud"
```

Example to create the virtualservice and gslbservice and generate a new certificate using Lets Encrypt:
```
ansible-playbook main.yaml --vault-password-file=../vault_pass --extra-vars "ApplicationName=testapp1.company.com ApplicationType=https_termination Tenant=admin HealthMonitor=ping ListeningPort='443' sni=none PoolMembers='10.1.1.1,80,enabled' CloudName=Default-Cloud GenerateCertificate=True"
```