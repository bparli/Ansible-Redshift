#!/usr/bin/python

DOCUMENTATION = '''
---
module: redshift
description: add or delete Redshift Clusters and Redshift snapshots.  Requires boto3 to be installed and configured
options:
    Command:
        description:
            - The Redshift task, create Redshift cluster, delete Redshift cluster, delete snapshot, snapshot Redshift cluster
        required: true
        choices: [ 'create', 'delete', 'snapshot']
    DBName:
        description:
            - "The name of the first database to be created when the cluster is created."
        required: false
    ClusterIdentifier:
        description:
            - "A unique identifier for the cluster."
        required: true
    ClusterType:
        description:
            - "The type of the cluster. When cluster type is specified as single-node or multi-node"
        required: false
        default: multi-node
        choices : ['single-node', 'multi-node']
    NodeType:
        description:
            - "The node type to be provisioned for the cluster."
        required: true
        choices : ['ds1.xlarge',  'ds1.8xlarge',  'ds2.xlarge', 'ds2.8xlarge', 'dc1.xlarge', 'dc1.8xlarge']
    MasterUsername:
        description:
            - "The user name associated with the master user account for the cluster that is being created."
        required: true
    MasterUserPassword:
        description:
            - "The password associated with the master user account for the cluster that is being created."
        required: true
    ClusterSecurityGroups:
        description:
            - "A list of security groups to be associated with this cluster."
        required: false
        default: "The default cluster security group for Amazon Redshift."
    VpcSecurityGroupIds:
        description:
            - "A list of Virtual Private Cloud (VPC) security groups to be associated with the cluster."
        required: false
        default: "The default VPC security group is associated with the cluster."
    ClusterSubnetGroupName:
        description:
            - "The name of a cluster subnet group to be associated with this cluster."
        required: false
        default: "If this parameter is not provided the resulting cluster will be deployed outside virtual private cloud (VPC)."
    AvailabilityZone:
        description:
            - "The EC2 Availability Zone (AZ) in which you want Amazon Redshift to provision the cluster."
        required: false
        default: "A random, system-chosen Availability Zone in the region that is specified by the endpoint."
    PreferredMaintenanceWindow:
        description:
            - "The weekly time range (in UTC) during which automated cluster maintenance can occur."
        required: false
        default: "A 30-minute window selected at random from an 8-hour block of time per region, occurring on a random day of the week."
    ClusterParameterGroupName:
        description:
            - "The name of the parameter group to be associated with this cluster."
        required: false
        default: "The default Amazon Redshift cluster parameter group."
    AutomatedSnapshotRetentionPeriod:
        description:
            - "The number of days that automated snapshots are retained."
        required: false
        default: 1
    Port:
        description:
            - "The port number on which the cluster accepts incoming connections."
        required: false
        default: 5439
    NumberOfNodes:
        description:
            - "The number of compute nodes in the cluster."
        required: false
        default: If you don't specify this parameter, you get a single-node cluster."
    PubliclyAccessible:
        description:
            - "If true , the data in the cluster is encrypted at rest."
        required: false
    Encrypted:
        description:
            - "If true , the cluster can be accessed from a public network."
        required: false
        default: false
    HsmClientCertificateIdentifier:
        description:
            - "Specifies the name of the HSM client certificate the Amazon Redshift cluster uses to retrieve the data encryption keys stored in an HSM."
        required: false
    HsmConfigurationIdentifier:
        description:
            - "Specifies the name of the HSM configuration that contains the information the Amazon Redshift cluster can use to retrieve and store keys in an HSM."
        required: false
    ElasticIp:
        description:
            - "The Elastic IP (EIP) address for the cluster."
        required: false
    KmsKeyId:
        description:
            - "The AWS Key Management Service (KMS) key ID of the encryption key that you want to use to encrypt data in the cluster."
        required: false
    Tags:
        description:
            - "A list of tag instances."
        required: false
    SkipFinalClusterSnapshot:
        description:
            - "A list of tag instances."
        required: false
        default: true
    FinalClusterSnapshotIdentifier:
        description:
            - "The identifier of the final snapshot that is to be created immediately before deleting the cluster."
        required: false
    SnapshotIdentifier:
        description:
            - "A unique identifier for the snapshot that you are requesting. "
        required: true (for snapshot command)

author: "Ben Parli"
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.
- redshift:
    Command: create
    ClusterIdentifier= mycluster
    DBName: test
    ClusterType: single-node
    NodeType: dw1.xlarge
    MasterUsername: testuser
    MasterUserPassword: passworD1234
    AvailabilityZone: us-west-2b

- redshift:
    Command: create
    ClusterIdentifier=mycluster
    DBName: test
    ClusterType: multi-node
    NumberOfNodes: 4
    NodeType: dw1.xlarge
    MasterUsername: testuser
    MasterUserPassword: passworD1234
    AvailabilityZone: us-west-2b
    tags:
      example1: tag1
      example2: tag2

- redshift:
    Command: snapshot
    ClusterIdentifier=mycluster
    SnapshotIdentifier=mysnapshot

- redshift:
    Command: delete
    ClusterIdentifier=mycluster
    FinalClusterSnapshotIdentifier=finalsnapshot

- redshift:
    Command: delete
    SnapshotIdentifier=mysnapshot
'''

import time

HAS_BOTO = True
try:
    import boto3
    import botocore
    client = boto3.client('redshift')
except ImportError:
    HAS_BOTO = False


class RedshiftConnection:
    def __init__(self, module, region, **aws_connect_params):
        try:
            self.connection = boto3.client('redshift', aws_access_key_id=aws_connect_params['aws_access_key_id'],
                                           aws_secret_access_key=aws_connect_params['aws_secret_access_key'])
        except:
             module.fail_json(msg="couldn't connect to redshift")

    def create_cluster(self, cluster_identifier, node_type, master_username, master_user_password, **params):
        try:
            result = self.connection.create_cluster(ClusterIdentifier=cluster_identifier,
                                                    NodeType=node_type, MasterUsername=master_username,
                                                    MasterUserPassword=master_user_password, **params)
            return self.get_cluster(result['Cluster']['ClusterIdentifier'])
        except botocore.exceptions.ClientError as e:
             self.module.fail_json(msg="Failed to create cluster: %s" % e.message)

    def create_cluster_snapshot(self, cluster_identifier, snapshot_identifier, **params):
        try:
            result = self.connection.create_cluster_snapshot(ClusterIdentifier=cluster_identifier,
                                                             SnapshotIdentifier = snapshot_identifier,
                                                             **params)
            return self.get_snapshot(snapshot_identifier)
        except botocore.exceptions.ClientError as e:
            self.module.fail_json(msg="Failed to create snapshot: %s" % e.message)

    def delete_cluster(self, cluster_identifier, **params):
        try:
            result = self.connection.delete_cluster(**params)
            return RedshiftCluster(result['Cluster'])
        except botocore.exceptions.ClientError as e:
            self.module.fail_json(msg="Failed to delete cluster: %s" % e.message)

    def delete_cluster_snapshot(self, snapshot, **params):
        try:
            result = self.connection.delete_cluster_snapshot(SnapshotIdentifier=snapshot)
            return RedshiftSnapshot(result['Snapshot'])
        except botocore.exceptions.ClientError as e:
            self.module.fail_json(msg="Failed to delete snapshot: %s" % e.message)

    def get_cluster(self, cluster_id):
        try:
            clusters = self.connection.describe_clusters(ClusterIdentifier=cluster_id)['Clusters']
            present = False
            for clust in clusters:
                if clust['ClusterIdentifier'] == cluster_id:
                    return RedshiftCluster(clust)
            if present == False:
                return None
        except botocore.exceptions.ClientError as e:
            return None

    def get_snapshot(self, snapshot):
        try:
            snapshots = self.connection.describe_cluster_snapshots(SnapshotIdentifier=snapshot)['Snapshots']
            if len(snapshots) > 0:
                return  RedshiftSnapshot(snapshots[0])
        except botocore.exceptions.ClientError as e:
            return None

class RedshiftException(Exception):
    def __init__(self, exc):
        if hasattr(exc, 'error_message') and exc.error_message:
            self.message = exc.error_message
            self.code = exc.error_code
        elif hasattr(exc, 'body') and 'Error' in exc.body:
            self.message = exc.body['Error']['Message']
            self.code = exc.body['Error']['Code']
        else:
            self.message = str(exc)
            self.code = 'Unknown Error'

class RedshiftSnapshot:
    def __init__(self, snapshot):
        time.sleep(5)
        self.snapshot = snapshot
        self.status = snapshot['Status']
        self.id = snapshot['SnapshotIdentifier']
        self.create_time = snapshot['SnapshotCreateTime']

    def get_data(self):
        data = {
            'id'    : self.id,
            'Status'    : self.status,
            'SnapshotCreateTime'    : self.create_time,
            'NodeType'  : self.snapshot['NodeType'],
            'NumberOfNodes' :   self.snapshot['NumberOfNodes'],
            'ClusterCreateTime' :   self.snapshot['ClusterCreateTime']
        }
        if self.status == 'available':
            data['Port'] = self.snapshot['Port']

        return data

class RedshiftCluster:
    def __init__(self, cluster):
        time.sleep(5)
        self.cluster = cluster
        self.status = cluster['ClusterStatus']
        self.id = cluster['ClusterIdentifier']

    def get_data(self):
        data = {
            'id'    : self.id,
            'Status'    : self.status,
            'NodeType'  : self.cluster['NodeType'],
            'ClusterSecurityGroups' :   [],
            'NumberOfNodes' :   self.cluster['NumberOfNodes']
        }
        try:
            data['AvailabilityZone'] = self.cluster['AvailabilityZone']
        except:
            data['AvailabilityZone'] = ''
        try:
            data['DBName'] = self.cluster['DBName']
        except:
            data['DBName'] = ''
        try:
            data['ClusterSubnetGroupName'] = self.cluster['ClusterSubnetGroupName']
        except:
            data['ClusterSubnetGroupName'] = ''
        try:
            data['ClusterCreateTime'] = self.cluster['ClusterCreateTime']
        except:
            data['ClusterCreateTime'] = ''

        if len(self.cluster['ClusterSecurityGroups']) > 0:
            for e in self.cluster['ClusterSecurityGroups']:
                data['ClusterSecurityGroups'].append(e['ClusterSecurityGroupName'])
        else:
            data['ClusterSecurityGroups'] = None
        if self.status == 'available':
            data['Port'] = self.cluster['Endpoint']['Port']
            data['Address']  = self.cluster['Endpoint']['Address']
        else:
            data["endpoint"] = None
            data["port"] = None
            data["vpc_security_groups"] = None
        return data

def validate_params(required_vars, valid_vars, module):
    command = module.params.get('Command')
    for v in required_vars:
        if not module.params.get(v):
            module.fail_json(msg="Parameter %s required for %s command" % (v, command))
    params = {}
    for k in valid_vars:
        if module.params.get(k) and k not in required_vars:
            if k in valid_vars:
                params[k] = module.params[k]
            else:
                module.fail_json(msg="Parameter %s is not valid for %s command" % (k, command))

    if module.params.get('ClusterSecurityGroups'):
        params['ClusterSecurityGroup'] = module.params.get('ClusterSecurityGroup').split(',')

    if 'Tags' in params:
        params['Tags'] = module.params['Tags'].items()
    return params

def create_cluster(module, conn):
    required_vars = ['ClusterIdentifier', 'NodeType', 'MasterUsername', 'MasterUserPassword']
    valid_vars = ['DBName', 'ClusterSecurityGroups', 'VpcSecurityGroupIds',
                  'ClusterSubnetGroupName', 'AvailabilityZone', 'PreferredMaintenanceWindow',
                  'ClusterParameterGroupName', 'AutomatedSnapshotRetentionPeriod',
                  'Port', 'NumberOfNodes', 'Encrypted', 'ElasticIp', 'HsmClientCertificateIdentifier',
                  'HsmConfigurationIdentifier', 'ElasticIp', 'KmsKeyId', 'Tags', 'PubliclyAccessible',
                  'ClusterType']

    params = validate_params(required_vars, valid_vars, module)
    cluster = module.params.get('ClusterIdentifier')
    result = conn.get_cluster(cluster)
    if result:
        changed = False
    else:
        try:
            result = conn.create_cluster(cluster, module.params.get('NodeType'),
                                         module.params.get('MasterUsername'),
                                        module.params.get('MasterUserPassword'), **params)
            changed = True
        except RedshiftException, e:
            module.fail_json(msg="Failed to create cluster: %s" % e.message)

    module.exit_json(changed=changed, cluster=result.get_data())

def create_cluster_snapshot(module, conn):
    required_vars = ['SnapshotIdentifier', 'ClusterIdentifier']
    valid_vars = ['Tags']
    params = validate_params(required_vars, valid_vars, module)

    cluster = module.params.get('ClusterIdentifier')
    snapshot = module.params.get('SnapshotIdentifier')
    result = conn.get_snapshot(snapshot)

    if result:
        changed = False
    else:
        try:
            result = conn.create_cluster_snapshot(cluster, snapshot, **params)
            changed = True
        except RedshiftException, e:
            module.fail_json(msg="Failed to create snapshot: %s" % e.message)

    module.exit_json(changed=changed, snapshot=result.get_data())

def delete_cluster(module, conn):
    required_vars = []
    valid_vars = ['ClusterIdentifier', 'SkipFinalClusterSnapshot', 'FinalClusterSnapshotIdentifier',
                  'SnapshotIdentifier']

    params = validate_params(required_vars, valid_vars, module)
    cluster = module.params.get('ClusterIdentifier')
    snapshot = module.params.get('SnapshotIdentifier')
    if not cluster:
        result = conn.get_snapshot(snapshot)
    else:
        result = conn.get_cluster(cluster)
    if not result:
        module.exit_json(changed=False)
    if result.status == 'deleting':
        module.exit_json(changed=False)
    try:
        if cluster:
            if snapshot:
                params['SkipFinalClusterSnapshot'] = False
                params['FinalClusterSnapshotIdentifier'] = module.params.get('FinalClusterSnapshotIdentifier')
            elif 'FinalClusterSnapshotIdentifier' not in params:
                params["SkipFinalClusterSnapshot"] = True
            result = conn.delete_cluster(cluster, **params)
        else:
            result = conn.delete_cluster_snapshot(snapshot)
    except RedshiftException, e:
        module.fail_json(msg="Failed to delete cluster: %s" % e.message)
    module.exit_json(changed=True)

def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            Command           = dict(choices=['create', 'delete', 'snapshot'], required=True),
            DBName           = dict(required=False),
            ClusterIdentifier        = dict(required=False),
            ClusterType      = dict(choices=['single-node', 'multi-node'], required=False, default='single-node'),
            NodeType         = dict(choices=['ds1.xlarge',  'ds1.8xlarge',  'ds2.xlarge', 'ds2.8xlarge', 'dc1.xlarge', 'dc1.8xlarge'], required=False),
            MasterUsername   = dict(required=False),
            MasterUserPassword = dict(required=False),
            ClusterSecurityGroups = dict(required=False, type='list'),
            VpcSecurityGroupIds = dict(required=False, type='list'),
            ClusterSubnetGroupName = dict(required=False),
            AvailabilityZone = dict(required=False),
            PreferredMaintenanceWindow = dict(required=False),
            ClusterParameterGroupName = dict(required=False),
            AutomatedSnapshotRetentionPeriod = dict(required=False),
            Port               = dict(required=False, type='int'),
            NumberOfNodes    = dict(required=False, type='int'),
            PubliclyAccessible = dict(required=False),
            Encrypted          = dict(required=False),
            HsmClientCertificateIdentifier = dict(required=False),
            HsmConfigurationIdentifier = dict(required=False),
            ElasticIp         = dict(required=False),
            KmsKeyId         = dict(required=False),
            Tags               = dict(required=False, type='dict'),
            SkipFinalClusterSnapshot    = dict(type='bool', required=False),
            FinalClusterSnapshotIdentifier = dict(required=False),
            SnapshotIdentifier  = dict(required=False)
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
    )
    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')
    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)
    try:
        conn = RedshiftConnection(module, region, **aws_connect_params)
    except:
        return 1

    if module.params.get('Command') == 'create':
        create_cluster(module, conn)
    elif module.params.get('Command') == 'delete':
        delete_cluster(module, conn)
    elif module.params.get('Command') == 'snapshot':
        create_cluster_snapshot(module, conn)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
