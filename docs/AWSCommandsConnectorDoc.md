## About the connector
AWS Commands are used to run AWS native commands for AWS resources configurations directly from FortiSOAR.
<p>This document provides information about the AWS Commands Connector, which facilitates automated interactions, with a AWS Commands server using FortiSOAR&trade; playbooks. Add the AWS Commands Connector as a step in FortiSOAR&trade; playbooks and perform automated operations with AWS Commands.</p>

### Version information

Connector Version: 1.0.0


Authored By: Fortinet

Certified: No
## Installing the connector
<p>Use the <strong>Content Hub</strong> to install the connector. For the detailed procedure to install a connector, click <a href="https://docs.fortinet.com/document/fortisoar/0.0.0/installing-a-connector/1/installing-a-connector" target="_top">here</a>.</p><p>You can also use the <code>yum</code> command as a root user to install the connector:</p>
<pre>yum install cyops-connector-aws-commands</pre>

## Prerequisites to configuring the connector
- You must have the credentials of AWS Commands server to which you will connect and perform automated operations.
- The FortiSOAR&trade; server should have outbound connectivity to port 443 on the AWS Commands server.

## Minimum Permissions Required
- Not applicable

## Configuring the connector
For the procedure to configure a connector, click [here](https://docs.fortinet.com/document/fortisoar/0.0.0/configuring-a-connector/1/configuring-a-connector)
### Configuration parameters
<p>In FortiSOAR&trade;, on the Connectors page, click the <strong>AWS Commands</strong> connector row (if you are in the <strong>Grid</strong> view on the Connectors page) and in the <strong>Configurations</strong> tab enter the required configuration details:</p>
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Configuration Type</td><td>Select configuration type that is how you want to provide credentials.
<br><strong>If you choose 'IAM Role'</strong><ul><li>AWS Instance IAM Role: IAM Role of your AWS instance to access AWS services.</li></ul><strong>If you choose 'Access Credentials'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>AWS Access Key ID: ID of the AWS Access Key to access AWS services.</li><li>AWS Secret Access Key: Key of the AWS Secret Access to access AWS services.</li></ul></td>
</tr></tbody></table>

## Actions supported by the connector
The following automated operations can be included in playbooks and you can also use the annotations to access operations from FortiSOAR&trade; release 4.10.0 and onwards:
<table border=1><thead><tr><th>Function</th><th>Description</th><th>Annotation and Category</th></tr></thead><tbody><tr><td>Execute AWS Command</td><td>Executes an AWS command on the host based on the command and other input parameters that you have specified.</td><td>generic_command <br/>Investigation</td></tr>
<tr><td>Get AMIs Detail</td><td>Retrieves details for all AMIs (Amazon Machine Images) or specific AMIs, based on input parameters you have specified from AWS.</td><td>get_ami_details <br/>Investigation</td></tr>
<tr><td>Launch Instance</td><td>Launches a new instance on AWS having basic configuration based on the image ID, instance type, and other input parameters you have specified.</td><td>launch_instance <br/>Miscellaneous</td></tr>
<tr><td>Get Instance Details</td><td>Retrieves details for an instance you have specified, using the instance ID from AWS Commands.</td><td>get_instance_info <br/>Investigation</td></tr>
<tr><td>Start Instance</td><td>Starts an instance you have specified using the instance ID on AWS Commands.</td><td>start_instance <br/>Miscellaneous</td></tr>
<tr><td>Stop Instance</td><td>Stops an instance you have specified using the instance ID on AWS Commands.</td><td>stop_instance <br/>Miscellaneous</td></tr>
<tr><td>Reboot Instance</td><td>Reboots an instance you have specified using the instance ID on AWS Commands.</td><td>reboot_instance <br/>Miscellaneous</td></tr>
<tr><td>Add Instance Tag</td><td>Adds a tag to an available AWS Commands instance you have specified using the instance ID.</td><td>add_tag <br/>Miscellaneous</td></tr>
<tr><td>Register Instance To ELB</td><td>Registers an AWS Commands instance to the elastic load balancing (ELB) service on AWS based on the ELB name and instance ID you have specified</td><td>register_instance <br/>Miscellaneous</td></tr>
<tr><td>Deregister Instance from ELB</td><td>Deregisters an instance from the elastic load balancing (ELB) service based on the ELB name and instance ID you have specified.</td><td>deregister_instance <br/>Miscellaneous</td></tr>
<tr><td>Attach Instance To Auto Scaling Group</td><td>Attaches a running instance to the auto scaling group on AWS Commands based on the auto scaling group name and instance ID (s) you have specified.</td><td>attach_instance <br/>Miscellaneous</td></tr>
<tr><td>Detach Instance From Auto Scaling Group</td><td>Detaches an EC2 instance from the auto scaling group on AWS Commands based on the auto scaling group name and instance ID (s) you have specified.</td><td>detach_instance <br/>Miscellaneous</td></tr>
<tr><td>Instance API Termination </td><td>Terminates an instance on AWS Commands using the REST API, if you have enabled this operation based on the instance ID and action you have specified.</td><td> <br/></td></tr>
<tr><td>Terminate Instance</td><td>Terminates an AWS Commands instance you have specified using the instance ID.</td><td>terminate_instance <br/>Miscellaneous</td></tr>
<tr><td>Attach Volume</td><td>Attaches a volume to an AWS Commands instance based on the volume ID, Device Name, and instance ID you have specified.</td><td>attach_volume <br/>Miscellaneous</td></tr>
<tr><td>Capture Volume Snapshot</td><td>Captures a snapshot of a volume on AWS Commands based on the volume ID and volume description you have specified.</td><td>get_snapshot_volume <br/>Miscellaneous</td></tr>
<tr><td>Detach Volume</td><td>Detaches a volume from an AWS Commands instance based on the volume ID, Device Name, and instance ID you have specified.</td><td>detach_volume <br/>Remediation</td></tr>
<tr><td>Delete Volume</td><td>Deletes a volume you have specified, using the volume ID.</td><td>delete_volume <br/>Remediation</td></tr>
<tr><td>Create Network ACL</td><td>Creates a network ACL in AWS Commands in the VPC you have specified.</td><td>create_network_acl <br/>Containment</td></tr>
<tr><td>Add Network ACL Rule</td><td>Adds a rule to the network access control list (ACL) on AWS Commands based on the network ACL ID, egress rule, and other input parameters you have specified.</td><td>add_rule <br/>Containment</td></tr>
<tr><td>Get Details of Network ACLs</td><td>Retrieves details of one or more of your network ACLs from AWS Commands, based on the Network ACL IDs and filters you have specified. Note: If you do not specify any network ACL ID or any filter, then details of all the network ACLs are retrieved from AWS Commands.</td><td>get_details_of_network_acls <br/>Investigation</td></tr>
<tr><td>Delete Network ACL Rule</td><td>Deletes the network ACL from AWS Commands,  based on the network ACL ID, Egress rule, and rule number you have specified.</td><td>delete_network_acl_rule <br/>Containment</td></tr>
<tr><td>Delete Network ACL</td><td>Deletes the specified network ACL. from AWS Commands, based on the Network ACL ID you have specified.</td><td>delete_network_acl <br/>Containment</td></tr>
<tr><td>Get User Details</td><td>Retrieves details for a user you have specified, using the username from AWS Commands.</td><td>get_user_info <br/>Investigation</td></tr>
<tr><td>Create Security Groups</td><td>Creates a new security group in the AWS Commands service based on the group name and description you have specified.</td><td>create_security_group <br/>Containment</td></tr>
<tr><td>Get Security Groups</td><td>Retrieves details of all security groups from the AWS Commands service.</td><td>get_security_groups <br/>Investigation</td></tr>
<tr><td>Get Details of Security Group</td><td>Retrieves details of given security group from the AWS Commands service.</td><td>get_details_of_security_group <br/>Investigation</td></tr>
<tr><td>Add Security Group To Instance</td><td>Adds a security group to an AWS Commands instance based on the security group name(s) or ID(s) and instance ID you have specified.</td><td>add_group <br/>Containment</td></tr>
<tr><td>Delete Security Groups</td><td>Deletes a security group you have specified, using the security group ID.</td><td>delete_security_group <br/>Remediation</td></tr>
<tr><td>Authorize Ingress</td><td>Adds (authorizes) ingress rules to a security group on AWS Commands based on the security group ID, CIDR IP value, and other input parameters you have specified.</td><td>authorize_ingress <br/>Containment</td></tr>
<tr><td>Authorize Egress</td><td>Adds (authorizes) egress rules to a security group on AWS Commands based on the security group ID, and IP permissions you have specified.</td><td>authorize_egress <br/>Containment</td></tr>
<tr><td>Revoke Egress</td><td>Removes (revokes) egress rules from a security group on AWS Commands based on the security group ID, and IP permissions you have specified.</td><td>revoke_egress <br/>Containment</td></tr>
<tr><td>Revoke Ingress</td><td>Removes (revokes) ingress rules from a security group on AWS Commands based on the security group ID, CIDR IP value, and other input parameters you have specified.</td><td>revoke_ingress <br/>Containment</td></tr>
</tbody></table>

### operation: Execute AWS Command
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Command</td><td>Specify the AWS command, without the aws, to run on the host. For example, if you want to run the command aws ec2 describe-instances to list all EC2 instances, Specify ec2 describe-instances in this field.
<br></td></tr><tr><td>Parameters</td><td>Specify a parameter name and its value to filter the results returned by the command. For information on parameters, refer https://docs.aws.amazon.com/cli/#latest-version
<br></td></tr></tbody></table>

#### Output

 The output contains a non-dictionary value.
### operation: Get AMIs Detail
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Image IDs</td><td>List of IDs of the AMIs whose details you want to retrieve from AWS Commands.
</td></tr><tr><td>Executable Users</td><td>List of AWS Account IDs of executable users(s) associated with the AMI(s) whose details you want to retrieve from AWS Commands.
</td></tr><tr><td>Owners</td><td>List of AWS Account IDs of owners associated with the AMI(s) whose details you want to retrieve from AWS Commands..
</td></tr><tr><td>Filters</td><td>List of filters based on which you want to retrieve details of AMIs from AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Images": [
        {
            "Architecture": "",
            "CreationDate": "",
            "ImageId": "",
            "ImageLocation": "",
            "ImageType": "",
            "Public": "",
            "OwnerId": "",
            "State": "",
            "BlockDeviceMappings": [],
            "Description": "",
            "Hypervisor": "",
            "Name": "",
            "RootDeviceName": "",
            "RootDeviceType": "",
            "SriovNetSupport": "",
            "VirtualizationType": ""
        }
    ],
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "content-type": "",
            "content-length": "",
            "vary": "",
            "date": "",
            "server": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Launch Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Image ID</td><td>ID of the AMI on which you want to launch a new instance. You can get the ID of an AMI using the Get AMIs Detail operation.
</td></tr><tr><td>Instance Type</td><td>Type of the instance that you want to launch on AWS Commands. For example, t1.micro
</td></tr><tr><td>Instance MaxCount</td><td>Maximum number of instances to launch on AWS Commands. If you specify a maximum that is greater than the maximum number of instances Amazon EC2 can launch in the target Availability Zone, Amazon EC2 launches the largest possible number of instances above MinCount.
</td></tr><tr><td>Instance MinCount</td><td>Minimum number of instances to launch on AWS Commands. If you specify a minimum that is lesser than the minimum number of instances than Amazon EC2 can launch in the target Availability Zone, Amazon EC2 launches no instances.
</td></tr><tr><td>SubNet ID</td><td>ID of the subnet associated with the network string.ID of a subnet must be provided if you don't want to use default subnet to this instance
</td></tr><tr><td>Device Name</td><td>Name of the device. For example, /dev/sdh or xvdh.
</td></tr><tr><td>Instance Delete on Termination</td><td>Select this option if you want to delete the interface when the instance is terminated.
</td></tr><tr><td>Security Group IDs</td><td>SD(s) of the security group(s) to be assigned to the newly launched instance on AWS Commands.
</td></tr><tr><td>Purpose For Launch Instance</td><td>Purpose of launching the instance on AWS Commands.
</td></tr><tr><td>Customer Name</td><td>Name of the customer for whom you are requesting the launch of the new instance on AWS Commands.
</td></tr><tr><td>Terminate by Date</td><td>Date on which the instance will be terminated on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPHeaders": {
            "date": "",
            "vary": "",
            "transfer-encoding": "",
            "content-type": "",
            "server": ""
        },
        "RequestId": "",
        "HTTPStatusCode": "",
        "RetryAttempts": ""
    },
    "InstanceId": "",
    "InstanceType": {
        "Value": ""
    }
}</pre>
### operation: Get Instance Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance for which you want to retrieve details from AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPHeaders": {
            "transfer-encoding": "",
            "vary": "",
            "content-type": "",
            "server": "",
            "date": ""
        },
        "HTTPStatusCode": "",
        "RetryAttempts": "",
        "RequestId": ""
    },
    "Reservations": [
        {
            "OwnerId": "",
            "Groups": [],
            "RequesterId": "",
            "ReservationId": "",
            "Instances": [
                {
                    "Monitoring": {
                        "State": ""
                    },
                    "VirtualizationType": "",
                    "RootDeviceName": "",
                    "InstanceId": "",
                    "EbsOptimized": "",
                    "LaunchTime": "",
                    "SecurityGroups": [],
                    "AmiLaunchIndex": "",
                    "Hypervisor": "",
                    "StateReason": {
                        "Message": "",
                        "Code": ""
                    },
                    "KeyName": "",
                    "Architecture": "",
                    "BlockDeviceMappings": [],
                    "State": {
                        "Name": "",
                        "Code": ""
                    },
                    "InstanceType": "",
                    "ImageId": "",
                    "Placement": {
                        "Tenancy": "",
                        "GroupName": "",
                        "AvailabilityZone": ""
                    },
                    "NetworkInterfaces": [],
                    "StateTransitionReason": "",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "PrivateDnsName": "",
                    "EnaSupport": "",
                    "ClientToken": "",
                    "RootDeviceType": ""
                }
            ]
        }
    ]
}</pre>
### operation: Start Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to start on AWS Commands.
</td></tr><tr><td>Purpose</td><td>Purpose of starting the instance on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPHeaders": {
            "date": "",
            "server": "",
            "content-type": "",
            "content-length": "",
            "x-amzn-requestid": ""
        },
        "RetryAttempts": "",
        "HTTPStatusCode": ""
    },
    "StartingInstances": [
        {
            "InstanceId": "",
            "CurrentState": {
                "Code": "",
                "Name": ""
            },
            "PreviousState": {
                "Code": "",
                "Name": ""
            }
        }
    ]
}</pre>
### operation: Stop Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to stop on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "StoppingInstances": [
        {
            "InstanceId": "",
            "CurrentState": {
                "Code": "",
                "Name": ""
            },
            "PreviousState": {
                "Code": "",
                "Name": ""
            }
        }
    ],
    "ResponseMetadata": {
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {},
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Reboot Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to reboot on AWS Commands
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RetryAttempts": "",
        "RequestId": "",
        "HTTPHeaders": {
            "date": "",
            "content-type": "",
            "vary": "",
            "transfer-encoding": "",
            "server": ""
        },
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Add Instance Tag
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the AWS Commands instance to which you want to add a tag.
</td></tr><tr><td>Tag Key</td><td>Key for the tag that you want to add.
</td></tr><tr><td>Value</td><td>Value for the tag that you want to add.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {},
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Register Instance To ELB
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>ELB Name</td><td>Name of the ELB to which you want to register the specified instance on AWS Commands.
</td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to register with the specified ELB on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Instances": [
        {
            "InstanceId": ""
        },
        {
            "InstanceId": ""
        }
    ],
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "date": "",
            "content-length": "",
            "x-amzn-requestid": "",
            "content-type": ""
        },
        "RetryAttempts": "",
        "RequestId": ""
    }
}</pre>
### operation: Deregister Instance from ELB
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>ELB Name</td><td>Name of the ELB from which you want to deregister the specified instance on AWS Commands.
</td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to deregister from the specified ELB on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Instances": [],
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "date": "",
            "content-length": "",
            "x-amzn-requestid": "",
            "content-type": ""
        },
        "RetryAttempts": "",
        "RequestId": ""
    }
}</pre>
### operation: Attach Instance To Auto Scaling Group
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Auto Scaling Group Name</td><td>Name of the auto scaling group to which you want to attach the specified instance on AWS Commands.
</td></tr><tr><td>Instance IDs (In CSV or List Format)</td><td>ID(s) of the instance(s) that you want to attach to the specified auto scaling group using the CSV or list format on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "HTTPHeaders": {
            "x-amzn-requestid": "",
            "date": "",
            "content-length": "",
            "content-type": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Detach Instance From Auto Scaling Group
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Auto Scaling Group Name (In CSV or List Format)</td><td>Name of the auto scaling group from which you want to detach the specified instance on AWS Commands.
</td></tr><tr><td>Instance IDs</td><td>ID of the instance that you want to detach from the specified auto scaling group on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Activities": [
        {
            "ActivityId": "",
            "StartTime": "",
            "Progress": "",
            "Cause": "",
            "AutoScalingGroupName": "",
            "Details": "",
            "Description": "",
            "StatusCode": ""
        }
    ],
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "HTTPHeaders": {
            "x-amzn-requestid": "",
            "date": "",
            "content-length": "",
            "content-type": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Instance API Termination 
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to terminate on AWS Commands using the REST API.
</td></tr><tr><td>Select Action</td><td>Specify Enable or Disable to either allow or disallow terminating an instance using the REST API.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {},
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Terminate Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the AWS Commands instance that you want to terminate.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "TerminatingInstances": [
        {
            "InstanceId": "",
            "CurrentState": {
                "Code": "",
                "Name": ""
            },
            "PreviousState": {
                "Code": "",
                "Name": ""
            }
        }
    ],
    "ResponseMetadata": {
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {},
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Attach Volume
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Volume Id</td><td>ID of the volume that you want to attach to the specified instance on AWS Commands.
</td></tr><tr><td>Device Name</td><td>Name (or full path) of the device on the specified instance on AWS Commands. For example, /dev/sdh or xvdh.
</td></tr><tr><td>Instance Id</td><td>ID of the instance to which you want to attach the specified volume on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Device": "",
    "AttachTime": "",
    "State": "",
    "InstanceId": "",
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {
            "transfer-encoding": "",
            "date": "",
            "server": "",
            "content-type": "",
            "vary": ""
        }
    },
    "VolumeId": ""
}</pre>
### operation: Capture Volume Snapshot
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Volume ID</td><td>ID of the volume on AWS Commands for which you want to capture a snapshot.
</td></tr><tr><td>Volume Description</td><td>Description of the snapshot.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "StartTime": "",
    "OwnerId": "",
    "Encrypted": "",
    "SnapshotId": "",
    "State": "",
    "VolumeId": "",
    "ResponseMetadata": {}
}</pre>
### operation: Detach Volume
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Volume Id</td><td>ID of the volume that you want to detach from the specified instance on AWS Commands.
</td></tr><tr><td>Device Name</td><td>Name (or full path) of the device on the specified instance on AWS Commands. For example, /dev/sdh or xvdh.
</td></tr><tr><td>Instance ID</td><td>ID of the instance from which you want to detach the specified volume on AWS Commands.
</td></tr><tr><td>Force To Detach</td><td>Select this option if you want to forcefully detach the volume from the specified instance on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Device": "",
    "AttachTime": "",
    "State": "",
    "InstanceId": "",
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {
            "transfer-encoding": "",
            "date": "",
            "server": "",
            "content-type": "",
            "vary": ""
        }
    },
    "VolumeId": ""
}</pre>
### operation: Delete Volume
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Volume ID</td><td>ID of the volume that you want to delete on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "RetryAttempts": "",
        "HTTPHeaders": {},
        "HTTPStatusCode": ""
    }
}</pre>
### operation: Create Network ACL
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>VPC ID</td><td>ID of the VPC in which you want to create the network ACL in AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "NetworkAcl": {
        "Associations": [],
        "Entries": [
            {
                "CidrBlock": "",
                "Egress": "",
                "IcmpTypeCode": {},
                "PortRange": {},
                "Protocol": "",
                "RuleAction": "",
                "RuleNumber": ""
            },
            {
                "CidrBlock": "",
                "Egress": "",
                "IcmpTypeCode": {},
                "PortRange": {},
                "Protocol": "",
                "RuleAction": "",
                "RuleNumber": ""
            }
        ],
        "IsDefault": "",
        "NetworkAclId": "",
        "Tags": [],
        "VpcId": "",
        "OwnerId": ""
    },
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "content-type": "",
            "content-length": "",
            "vary": "",
            "date": "",
            "server": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Add Network ACL Rule
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Network ACL ID</td><td>ID of the network in which you want to add the ACL rule on AWS Commands.
</td></tr><tr><td>Egress Rule</td><td>Select either Inbound_Rule or Outbound_Rule.
</td></tr><tr><td>IP Address</td><td>IP address of the network in which you want to add the ACL rule on AWS Commands.
</td></tr><tr><td>Rule Action</td><td>Action that the rule must perform. Choose between DENY or ALLOW.
</td></tr><tr><td>Rule Number</td><td>Position of where the rule must be placed in the ACL rules on AWS Commands.Constraints: Positive integer from 1 to 32766
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "HTTPHeaders": {
            "transfer-encoding": "",
            "server": "",
            "date": "",
            "vary": "",
            "content-type": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Get Details of Network ACLs
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Network ACL IDs</td><td>IDs of the network ACL whose details you want to retrieve from AWS Commands. Note: If you do not specify and ID then details of all the Network ACLs are retrieved from AWS Commands.
</td></tr><tr><td>Filters</td><td>Filters based on which you want to retrieve details for network ACL from AWS Commands. Format of the filter is: [{'Name': 'string','Values': ['string']}] For example, [{'Name': 'vpc-id','Values': ['vpc-a01106c2']}]
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "NetworkAcls": [
        {
            "Associations": [
                {
                    "NetworkAclAssociationId": "",
                    "NetworkAclId": "",
                    "SubnetId": ""
                }
            ],
            "Entries": [
                {
                    "CidrBlock": "",
                    "Egress": "",
                    "Protocol": "",
                    "RuleAction": "",
                    "RuleNumber": ""
                }
            ],
            "IsDefault": true,
            "NetworkAclId": "",
            "Tags": [],
            "VpcId": "",
            "OwnerId": ""
        }
    ],
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "content-type": "",
            "content-length": "",
            "vary": "",
            "date": "",
            "server": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Delete Network ACL Rule
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Network ACL ID</td><td>ID of the network from which you want to delete the ACL rule on AWS Commands.
</td></tr><tr><td>Egress Rule</td><td>Select either Inbound_Rule or Outbound_Rule.
</td></tr><tr><td>Rule Number</td><td>The rule number of the entry to delete.Constraints: Positive integer from 1 to 32766
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RequestId": "",
        "HTTPHeaders": {
            "transfer-encoding": "",
            "server": "",
            "date": "",
            "vary": "",
            "content-type": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Delete Network ACL
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Network ACL ID</td><td>ID of the network ACL that you want to delete from AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "content-type": "",
            "content-length": "",
            "vary": "",
            "date": "",
            "server": ""
        },
        "RetryAttempts": ""
    }
}</pre>
### operation: Get User Details
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Username</td><td>Name of the user for whom you want to retrieve details from AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "UserPolicies": "",
    "MFADevices": "",
    "UserGroups": "",
    "UserName": "",
    "CreateDate": "",
    "UserID": ""
}</pre>
### operation: Create Security Groups
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Group Name</td><td>Name of the new security group that you want to create on AWS Commands.
</td></tr><tr><td>Description</td><td>Description of the new security group that you want to create on AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPHeaders": {
            "content-length": "",
            "content-type": "",
            "server": "",
            "date": ""
        },
        "HTTPStatusCode": "",
        "RetryAttempts": ""
    },
    "GroupId": ""
}</pre>
### operation: Get Security Groups
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPHeaders": {
            "content-length": "",
            "content-type": "",
            "server": "",
            "date": "",
            "vary": ""
        },
        "HTTPStatusCode": "",
        "RetryAttempts": ""
    },
    "SecurityGroups": [
        {
            "VpcId": "",
            "Description": "",
            "OwnerId": "",
            "GroupName": "",
            "IpPermissionsEgress": [
                {
                    "PrefixListIds": [],
                    "IpProtocol": "",
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": ""
                        }
                    ]
                }
            ],
            "GroupId": "",
            "IpPermissions": [
                {
                    "FromPort": "",
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "IpProtocol": "",
                    "UserIdGroupPairs": [],
                    "ToPort": "",
                    "IpRanges": [
                        {
                            "CidrIp": ""
                        }
                    ]
                }
            ]
        }
    ]
}</pre>
### operation: Get Details of Security Group
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the Security Group to retrive details from AWS.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "RequestId": "",
        "HTTPHeaders": {
            "content-length": "",
            "content-type": "",
            "server": "",
            "date": "",
            "vary": ""
        },
        "HTTPStatusCode": "",
        "RetryAttempts": ""
    },
    "SecurityGroups": [
        {
            "VpcId": "",
            "Description": "",
            "OwnerId": "",
            "GroupName": "",
            "IpPermissionsEgress": [
                {
                    "PrefixListIds": [],
                    "IpProtocol": "",
                    "Ipv6Ranges": [],
                    "UserIdGroupPairs": [],
                    "IpRanges": [
                        {
                            "CidrIp": ""
                        }
                    ]
                }
            ],
            "GroupId": "",
            "IpPermissions": [
                {
                    "FromPort": "",
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "IpProtocol": "",
                    "UserIdGroupPairs": [],
                    "ToPort": "",
                    "IpRanges": [
                        {
                            "CidrIp": ""
                        }
                    ]
                }
            ]
        }
    ]
}</pre>
### operation: Add Security Group To Instance
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Instance ID</td><td>ID of the instance that you want to add to the specified Security Group(s) on AWS Commands.
</td></tr><tr><td>Security Group Name or ID (In CSV or List Format)</td><td>Name(s) or ID(s) of the Security Group(s) to which you want to add the specified instance on AWS Commands. The Security Group ID(s) or Name(s) must be specified in the CSV or list format.For example, ["default", "launch-wizard-3", "sg-9fc7dcf7"]
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "Response": {
        "ResponseMetadata": {}
    }
}</pre>
### operation: Delete Security Groups
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the security group ID that you want to delete from AWS Commands.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "status": "",
    "data": {
        "ResponseMetadata": {
            "HTTPStatusCode": "",
            "HTTPHeaders": {
                "content-type": "",
                "server": "",
                "date": "",
                "content-length": ""
            },
            "RetryAttempts": "",
            "RequestId": ""
        }
    },
    "operation": "",
    "message": "",
    "env": {}
}</pre>
### operation: Authorize Ingress
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the security group ID on AWS Commands in which you want to authorize (add) the ingress rule.
</td></tr><tr><td>IP Permissions</td><td>IP permissions required to Authorize ingress rules.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPHeaders": {
            "content-length": "",
            "content-type": "",
            "date": "",
            "server": ""
        },
        "RequestId": "",
        "HTTPStatusCode": "",
        "RetryAttempts": ""
    }
}</pre>
### operation: Authorize Egress
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the security group ID on AWS Commands in which you want to authorize (add) egress rules.
</td></tr><tr><td>IP Permissions</td><td>IP permissions required to authorize egress rules.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "RetryAttempts": "",
        "RequestId": "",
        "HTTPHeaders": {
            "content-length": "",
            "content-type": "",
            "server": "",
            "date": ""
        }
    }
}</pre>
### operation: Revoke Egress
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the security group ID on AWS Commands from which you want to revoke (remove) egress rules.
</td></tr><tr><td>IP Permissions</td><td>IP permissions required to revoke egress rules.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "ResponseMetadata": {
        "HTTPStatusCode": "",
        "HTTPHeaders": {
            "content-type": "",
            "date": "",
            "content-length": "",
            "server": ""
        },
        "RetryAttempts": "",
        "RequestId": ""
    }
}</pre>
### operation: Revoke Ingress
#### Input parameters
<table border=1><thead><tr><th>Parameter</th><th>Description</th></tr></thead><tbody><tr><td>Assume a Role</td><td>Select this option to assume a role.Note: You must enable this option, i.e., this parameter is required, if you have specified IAM Role as the Configuration Type. If you have specified Access Credentials as the Configuration Type, then this parameter is optional.If you select this option, then you must specify the following parameters: AWS Region: Your account's AWS region that you will use to access AWS services. Role ARN: ARN of the role that you want to assume to execute this action on AWS. Session Name: Name of the session that will be created to execute this action on AWS.
<br><strong>If you choose 'true'</strong><ul><li>AWS Region: Your account's AWS region that you will use to access AWS services.</li><li>Role ARN: ARN of the role that you want assume to execute this action on AWS.</li><li>Session Name: Name of the session that will be created to execute this action on AWS.</li></ul></td></tr><tr><td>Security Group ID</td><td>ID of the security group ID on AWS Commands from which you want to revoke (remove) the ingress rule.
</td></tr><tr><td>IP Permissions</td><td>IP permissions required to revoke ingress rules.
</td></tr></tbody></table>

#### Output
The output contains the following populated JSON schema:

<pre>{
    "status": "",
    "data": {
        "ResponseMetadata": {
            "HTTPStatusCode": "",
            "RetryAttempts": "",
            "HTTPHeaders": {
                "content-length": "",
                "server": "",
                "content-type": "",
                "date": ""
            },
            "RequestId": ""
        }
    },
    "operation": "",
    "env": {},
    "message": ""
}</pre>
## Included playbooks
The `Sample - aws-commands - 1.0.0` playbook collection comes bundled with the AWS Commands connector. These playbooks contain steps using which you can perform all supported actions. You can see bundled playbooks in the **Automation** > **Playbooks** section in FortiSOAR&trade; after importing the AWS Commands connector.

- Execute AWS Command
- Get AMIs Detail
- Launch Instance
- Get Instance Details
- Start Instance
- Stop Instance
- Reboot Instance
- Add Instance Tag
- Register Instance To ELB
- Deregister Instance from ELB
- Attach Instance To Auto Scaling Group
- Detach Instance From Auto Scaling Group
- Instance API Termination 
- Terminate Instance
- Attach Volume
- Capture Volume Snapshot
- Detach Volume
- Delete Volume
- Create Network ACL
- Add Network ACL Rule
- Get Details of Network ACLs
- Delete Network ACL Rule
- Delete Network ACL
- Get User Details
- Create Security Groups
- Get Security Groups
- Get Details of Security Group
- Add Security Group To Instance
- Delete Security Groups
- Authorize Ingress
- Authorize Egress
- Revoke Egress
- Revoke Ingress

**Note**: If you are planning to use any of the sample playbooks in your environment, ensure that you clone those playbooks and move them to a different collection since the sample playbook collection gets deleted during connector upgrade and delete.
