#!/usr/bin/python

#DOCUMENTATION = '''
'''module: redshift_cluster
short_description: add or delete Route53 zones
description:
    - Creates and deletes Route53 private and public zones
version_added: "2.0"
options:
    id:
        description:
            - "This is the unique key that identifies a cluster. This parameter is stored as a lowercase string. "
        required: true
    command:
        description: Create or delete
        required: true
        default: create
        choices: [ "create", "delete" ]
    database:
        description:
            - Optional. A default database named dev is created for the cluster. Optionally, specify a custom database name (e.g. mydb) to create an additional database.
        required: false
    db_port:
        description:
            - Port number on which the database accepts connections.
        required: true
        default: null
    db_user:
        description:
            - Name of master user for your cluster. (e.g. awsuser)
        required: true
        default: null
    user_pw:
        required: false
        default: ''
    node_type:
        required: true
        default: Single Node
    cluster_type:
        required: true
    num_nodes:
        required: true
        default: 1
    param_group:
        required: true
        default: default.redshift-1.0
    encrypt:
        required: true
        default: None
    vpc:
        required: true
        description: The identifier of the VPC in which you want to create your cluster
    sub_group:
        required: true
        description: Selected Cluster Subnet Group may limit the choice of Availability Zones
    public:
        required: true
    zone:
        required: false
        default: no preference
    sec_group:
        required: false
        default: default
    CloudWatch:
        required: false
        default: no

author: "Ben Parli"
'''

'''EXAMPLES = '''
# TODO '''

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
            self.connection = boto3.client('redshift', aws_access_key_id=aws_connect_params['aws_access_key_id'], aws_secret_access_key=aws_connect_params['aws_secret_access_key'])
        except:
             module.fail_json(msg="couldn't connect to redshift")

    def create_cluster(self, cluster_identifier, node_type, master_username, master_user_password, **params):
        try:
            result = self.connection.create_cluster(ClusterIdentifier=cluster_identifier, NodeType=node_type, MasterUsername=master_username, \
                                                    MasterUserPassword=master_user_password, **params)
            return self.get_cluster(result['Cluster']['ClusterIdentifier'])
        except botocore.exceptions.ClientError as e:
            raise RedshiftException(e)

    def create_cluster_snapshot(self, cluster_identifier, snapshot_identifier, **params):
        try:
            result = self.connection.create_cluster_snapshot(ClusterIdentifier=cluster_identifier, SnapshotIdentifier = snapshot_identifier,
                                                             **params)
            return self.get_snapshot(snapshot_identifier)
        except botocore.exceptions.ClientError as e:
            raise RedshiftException(e)

    def delete_cluster(self, cluster_identifier, **params):
        try:
            result = self.connection.delete_cluster(**params)
            return RedshiftCluster(result['Cluster'])
        except botocore.exceptions.ClientError as e:
            raise RedshiftException(e)

    def delete_cluster_snapshot(self, snapshot, **params):
        try:
            result = self.connection.delete_cluster_snapshot(SnapshotIdentifier=snapshot)
            return RedshiftSnapshot(result['Snapshot'])
        except botocore.exceptions.ClientError as e:
            raise RedshiftException(e)

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
    valid_vars = ['DBName', 'ClusterSecurityGroups', 'VpcSecurityGroupIds', 'ClusterSubnetGroupName', 'AvailabilityZone', \
                  'PreferredMaintenanceWindow', 'ClusterParameterGroupName', 'AutomatedSnapshotRetentionPeriod', \
                  'Port', 'NumberOfNodes', 'Encrypted', 'ElasticIp', 'HsmClientCertificateIdentifier', 'HsmConfigurationIdentifier',\
                  'ElasticIp', 'KmsKeyId', 'Tags', 'PubliclyAccessible', 'ClusterType']

    params = validate_params(required_vars, valid_vars, module)
    cluster = module.params.get('ClusterIdentifier')
    result = conn.get_cluster(cluster)
    if result:
        changed = False
    else:
        try:
            result = conn.create_cluster(cluster, module.params.get('NodeType'), module.params.get('MasterUsername'), \
                                        module.params.get('MasterUserPassword'), **params)
            changed = True
        except RedshiftException, e:
            module.fail_json(msg="Failed to create instance: %s" % e.message)

    module.exit_json(changed=changed, instance=result.get_data())

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
            module.fail_json(msg="Failed to create instance: %s" % e.message)

    module.exit_json(changed=changed, instance=result.get_data())

def delete_cluster(module, conn):
    required_vars = []
    valid_vars = ['ClusterIdentifier', 'SkipFinalClusterSnapshot', 'FinalClusterSnapshotIdentifier', 'SnapshotIdentifier']

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
                params["SkipFinalClusterSnapshot"] = False
                params["FinalSnapshotId"] = snapshot
            else:
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
            ClusterSecurityGroups = dict(required=False),
            VpcSecurityGroupIds = dict(required=False, type='list'),
            ClusterSubnetGroupName = dict(required=False),
            AvailabilityZone = dict(required=False),
            PreferredMaintenanceWindow = dict(required=False),
            ClusterParameterGroupName = dict(required=False),
            AutomatedSnapshotRetentionPeriod = dict(required=False),
            Port               = dict(required=False, type='int'),
            NumberOfNodes    = dict(required=False, type=int),
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
    #aws_connect_params = dict(aws_access_key_id='AKIAJRUYQ4BZZHV3AB2A', aws_secret_access_key='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',\
    #   security_token=None)
    #region = 'us-west-2'

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
