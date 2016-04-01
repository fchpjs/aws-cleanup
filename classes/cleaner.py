from boto3.session import Session
import botocore
import sys

class Cleaner:
    def __init__(self, config):
        self.config = config
                            
    def clean_all(self):
        print('Cleaning region specific resources...')
        for region in self.config['region_names']:
            print('\nRegion: ' + region)
            self.session = Session(
                aws_access_key_id=self.config['aws_access_key_id'],
                aws_secret_access_key=self.config['aws_secret_access_key'],
                region_name=region
            )
            self.clean_ec2()
        print('Cleaning region agnostic resources...')
        self.clean_iam()
        return True
        
    def clean_ec2(self):
        print('START ec2 clean')
        ec2 = self.session.resource('ec2')
        # clean instances
        for instance in ec2.instances.all():
            print('Terminating instance: ' + instance.id)
            try:
                instance.terminate(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print('Unable to terminate instance: ' + instance.id)
                print(e.response['Error']['Code'])
            except:
                print("Unexpected error:", sys.exc_info()[0])
        
        # clean keypairs
        for keypair in ec2.key_pairs.all():
            print('Deleting keypair: ' + keypair.name)
            try:
                keypair.delete(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print('Unable to delete keypair: ' + keypair.name)
                print(e.response['Error']['Code'])
            except:
                print("Unexpected error:", sys.exc_info()[0])
        
        # clean volumes
        for volume in ec2.volumes.all():
            print('Deleting volume: ' + volume.id)
            try:
                volume.delete(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to delete volume: ' + volume.id)
            except:
                print("Unexpected error:", sys.exc_info()[0])
        
        # clean images
        for image in ec2.images.filter(Owners=[self.config['aws_account_id']]):
            print('Deregistering images: ' + image.id)
            try:
                image.deregister(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to delete volume: ' + image.id)
            except:
                print("Unexpected error:", sys.exc_info()[0])
                
        # clean snapshots
        filters=[
            {
                'Name':'owner-id',
                'Values':[self.config['aws_account_id']]
            }
        ]
        for snapshot in ec2.snapshots.filter(Filters=filters):
            print('Deleting snapshot: ' + snapshot.id)
            try:
                snapshot.delete(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to delete snapshot: ' + snapshot.id)
            except:
                print("Unexpected error:", sys.exc_info()[0]) 
        
        # clean security groups
        for security_group in ec2.security_groups.all():
            if security_group.group_name == 'default':
                continue
            print('Deleting security group: ' + security_group.id)
            for ip_permission in security_group.ip_permissions:
                print('Deleting ingress rule: ' + ip_permission['IpProtocol'])
                security_group.revoke_ingress(IpPermissions=[ip_permission])
            for ip_permission in security_group.ip_permissions_egress:
                print('Deleting egress rule: ' + ip_permission['IpProtocol'])
                security_group.revoke_egress(IpPermissions=[ip_permission])
            try:
                security_group.delete(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to delete security group: ' + security_group.id)
            except:
                print("Unexpected error:", sys.exc_info()[0]) 
        
        # clean elastic ips
        print('Checking VPC addresses')
        for vpc_address in ec2.vpc_addresses.filter(PublicIps=[]):
            print('Releasing elastic ip: ' + vpc_address.public_ip)
            try:
                vpc_address.release(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to release elastic ip: ' + vpc_address.public_ip)
            except:
                print("Unexpected error:", sys.exc_info()[0]) 
        
        print('Checking classic addresses')
        for classic_address in ec2.classic_addresses.filter(PublicIps=[]):
            print('Releasing elastic ip: ' + classic_address.public_ip)        
            try:
                classic_address.release(DryRun=False)
            except botocore.exceptions.ClientError as e:
                print(e.response['Error']['Code'])
                print('Unable to release elastic ip: ' + classic_address.public_ip)
            except:
                print("Unexpected error:", sys.exc_info()[0])
                
        print('END ec2 clean')
        return True
        
        
            
    def clean_iam(self):
        print('START iam clean')
        client = self.session.client('iam')
        iam = self.session.resource('iam')
        for user in iam.users.all():
            print(user)
            if self.config['protected_users'].count(user.name) > 0:
                print('Skipping protected user: ' + user.name)
                continue
            self.delete_user(user)
        print('END iam clean')
        return True
    
    def delete_user(self, user):
        #remove groups
        for group in user.groups.all():
           user.remove_group(GroupName=group.name)
        #remove keys
        for access_key in user.access_keys.all():
            access_key.delete()
        #remove signing certs
        for signing_certificate in user.signing_certificates.all():
            signing_certificate.delete()
        #remove inline policies
        for policy in user.policies.all():
            policy.delete()
        #remove attached policies
        for policy in user.attached_policies.all():
            user.detach_policy(PolicyArn=policy.arn)
        #delete login_profile
        try:
            user.LoginProfile().delete()
        except botocore.exceptions.ClientError as e:
            print(e.response['Error']['Code'])
            print('Unable to delete login profile: ' + user.name)
        except:
            print("Unexpected error:", sys.exc_info()[0])
        #finally delete user
        user.delete()
        return True