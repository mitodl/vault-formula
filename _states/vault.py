from __future__ import absolute_import

import logging
import os

import salt.config
import salt.syspaths
import salt.utils
import salt.exceptions

log = logging.getLogger(__name__)

try:
    import hvac
    DEPS_INSTALLED = True
except ImportError:
    log.debug('Unable to import the HVAC library.')
    DEPS_INSTALLED = False

__all__ = ['initialize']


def __virtual__():
    return DEPS_INSTALLED


def initialized(name, secret_shares=5, secret_threshold=3, pgp_keys=None,
               keybase_users=None, unseal=True):
    """
    Ensure that the vault instance has been initialized and run the
    initialization if it has not.

    :param name: The id used for the state definition
    :param secret_shares: THe number of secret shares to use for the
                          initialization key
    :param secret_threshold: The number of keys required to unseal the vault
    :param pgp_keys: List of PGP public key strings to use for encrypting
                     the sealing keys
    :param keybase_users: List of Keybase users to retrieve public PGP keys
                          for to use in encrypting the sealing keys
    :param unseal: Whether to unseal the vault during initialization
    :returns: Result of the execution
    :rtype: dict
    """
    ret = {'name': name,
           'comment': '',
           'result': '',
           'changes': {}}
    initialized = __salt__['vault.is_initialized']()

    if initialized:
        ret['result'] = True
        ret['Comment'] = 'Vault is already initialized'
    elif __opts__['test']:
        ret['result'] = None
        ret['comment'] = 'Vault will be initialized.'
    else:
        success, sealing_keys, root_token = __salt__['vault.initialize'](
            secret_shares, secret_threshold, pgp_keys, keybase_users, unseal
        ) if not initialized else (True, {}, '')
        ret['result'] = success
        ret['changes'] = {
            'root_credentials': {
                'new': {
                    'sealing_keys': sealing_keys,
                    'root_token': root_token
                },
                'old': {}
            }
        }
        ret['comment'] = 'Vault has {}initialized'.format(
            '' if success else 'failed to be ')
    return ret


def auth_backend_enabled(name, backend_type, description='', mount_point=None):
    """
    Ensure that the named backend has been enabled

    :param name: ID for state definition
    :param backend_type: The type of authentication backend to enable
    :param description: The description to set for the backend
    :param mount_point: The root path at which the backend will be mounted
    :returns: The result of the state execution
    :rtype: dict
    """
    backends = __salt__['vault.list_auth_backends']()
    setting_dict = {'type': backend_type, 'description': description}
    backend_enabled = False
    ret = {'name': name,
           'comment': '',
           'result': '',
           'changes': {'old': backends}}

    for path, settings in __salt__['vault.list_auth_backends']().get('data', {}).items():
        if (path.strip('/') == mount_point or backend_type and
            settings['type'] == backend_type):
            backend_enabled = True

    if backend_enabled:
        ret['comment'] = ('The {auth_type} backend mounted at {mount} is already'
                          ' enabled.'.format(auth_type=backend_type,
                                             mount=mount_point))
        ret['result'] = True
    elif __opts__['test']:
        ret['result'] = None
    else:
        try:
            __salt__['vault.enable_auth_backend'](backend_type,
                                                  description=description,
                                                  mount_point=mount_point)
            ret['result'] = True
            ret['changes']['new'] = __salt__[
                'vault.list_auth_backends']()
        except __utils__['vault.vault_error']() as e:
            ret['result'] = False
            log.exception(e)
        ret['comment'] = ('The {backend} has been successfully mounted at '
                          '{mount}.'.format(backend=backend_type,
                                            mount=mount_point))
    return ret


def audit_backend_enabled(name, backend_type, description='', options=None,
                          backend_name=None):
    if not backend_name:
        backend_name = backend_type
    backends = __salt__['vault.list_audit_backends']().get('data', {})
    setting_dict = {'type': backend_type, 'description': description}
    backend_enabled = False
    ret = {'name': name,
           'comment': '',
           'result': '',
           'changes': {'old': backends}}

    for path, settings in __salt__['vault.list_audit_backends']().items():
        if (path.strip('/') == backend_type and
            settings['type'] == backend_type):
            backend_enabled = True

    if backend_enabled:
        ret['comment'] = ('The {audit_type} backend is already enabled.'
                          .format(audit_type=backend_type))
        ret['result'] = True
    elif __opts__['test']:
        ret['result'] = None
    else:
        try:
            __salt__['vault.enable_audit_backend'](backend_type,
                                                   description=description,
                                                   name=backend_name)
            ret['result'] = True
            ret['changes']['new'] = __salt__[
                'vault.list_audit_backends']()
            ret['comment'] = ('The {backend} audit backend has been '
                              'successfully enabled.'.format(
                                  backend=backend_type))
        except __utils__['vault.vault_error']() as e:
            ret['result'] = False
            log.exception(e)
    return ret


def secret_backend_enabled(name, backend_type, description='', mount_point=None,
                           connection_config_path=None, connection_config=None,
                           lease_max=None, lease_default=None, ttl_max=None,
                           ttl_default=None, override=False):
    """

    :param name: The ID for the state definition
    :param backend_type: The type of the backend to be enabled (e.g. MySQL)
    :param description: The description to set for the enabled backend
    :param mount_point: The root path for the backend
    :param connection_config_path: The full path to the endpoint used for
                                   configuring the connection (needed for
                                   e.g. Consul)
    :param connection_config: The configuration settings for the backend
                              connection
    :param lease_max: The maximum allowed lease for credentials retrieved from
                      the backend
    :param lease_default: The default allowed lease for credentials retrieved from
                          the backend
    :param ttl_max: The maximum TTL for a lease generated by the backend. Uses
                    the mounts/<mount_point>/tune endpoint.
    :param ttl_default: The default TTL for a lease generated by the backend.
                        Uses the mounts/<mount_point>/tune endpoint.
    :param override: Specifies whether to override the settings for an existing mount
    :returns: The result of the execution
    :rtype: dict

    """
    backends = __salt__['vault.list_secret_backends']().get('data', {})
    backend_enabled = False
    ret = {'name': name,
           'comment': '',
           'result': '',
           'changes': {'old': backends}}

    for path, settings in __salt__['vault.list_secret_backends']().get('data', {}).items():
        if (path.strip('/') == mount_point and
            settings['type'] == backend_type):
            backend_enabled = True

    if backend_enabled and not override:
        ret['comment'] = ('The {secret_type} backend mounted at {mount} is already'
                          ' enabled.'.format(secret_type=backend_type,
                                             mount=mount_point))
        ret['result'] = True
    elif __opts__['test']:
        ret['result'] = None
    else:
        try:
            __salt__['vault.enable_secret_backend'](backend_type,
                                                    description=description,
                                                    mount_point=mount_point)
            ret['result'] = True
            ret['changes']['new'] = __salt__[
                'vault.list_secret_backends']()
        except __utils__['vault.vault_error']() as e:
            ret['result'] = False
            log.exception(e)
        if connection_config:
            if not connection_config_path:
                connection_config_path = '{mount}/config/connection'.format(
                    mount=mount_point)
            try:
                __salt__['vault.write'](connection_config_path,
                                        **connection_config)
            except __utils__['vault.vault_error']() as e:
                ret['comment'] += ('The backend was enabled but the connection '
                                  'could not be configured\n')
                log.exception(e)
                raise salt.exceptions.CommandExecutionError(str(e))
        if ttl_max or ttl_default:
            ttl_config_path = 'sys/mounts/{mount}/tune'.format(
                mount=mount_point)
            if ttl_default > ttl_max:
                raise salt.exceptions.SaltInvocationError(
                    'The specified default ttl is longer than the maximum')
            if ttl_max and not ttl_default:
                ttl_default = ttl_max
            if ttl_default and not ttl_max:
                ttl_max = ttl_default
            try:
                log.debug('Tuning the mount ttl to be: Max={ttl_max}, '
                          'Default={ttl_default}'.format(
                              ttl_max=ttl_max, ttl_default=ttl_default))
                __salt__['vault.write'](ttl_config_path,
                                        default_lease_ttl=ttl_default,
                                        max_lease_ttl=ttl_max)
            except __utils__['vault.vault_error']() as e:
                ret['comment'] += ('The backend was enabled but the connection '
                                  'ttl could not be tuned\n'.format(e))
                log.exception(e)
                raise salt.exceptions.CommandExecutionError(str(e))
        if lease_max or lease_default:
            lease_config_path = '{mount}/config/lease'.format(
                mount=mount_point)
            if lease_default > lease_max:
                raise salt.exceptions.SaltInvocationError(
                    'The specified default lease is longer than the maximum')
            if lease_max and not lease_default:
                lease_default = lease_max
            if lease_default and not lease_max:
                lease_max = lease_default
            try:
                log.debug('Tuning the lease config to be: Max={lease_max}, '
                          'Default={lease_default}'.format(
                              lease_max=lease_max, lease_default=lease_default))
                __salt__['vault.write'](lease_config_path,
                                        ttl=lease_default,
                                        max_ttl=lease_max)
            except __utils__['vault.vault_error']() as e:
                ret['comment'] += ('The backend was enabled but the lease '
                                  'length could not be configured\n'.format(e))
                log.exception(e)
                raise salt.exceptions.CommandExecutionError(str(e))
        ret['comment'] += ('The {backend} has been successfully mounted at '
                          '{mount}.'.format(backend=backend_type,
                                            mount=mount_point))
    return ret

def app_id_created(name, app_id, policies, display_name=None,
                   mount_point='app-id', **kwargs):
    ret = {'name': app_id,
           'comment': '',
           'result': False,
           'changes': {}}
    current_id = __salt__['vault.get_app_id'](app_id, mount_point)
    if (current_id.get('data') is not None and
          current_id['data'].get('policies') == policies):
        ret['result'] = True
        ret['comment'] = ('The app-id {app_id} exists with the specified '
                          'policies'.format(app_id=app_id))
    elif __opts__['test']:
        ret['result'] = None
        if current_id['data'] is None:
            ret['changes']['old'] = {}
            ret['comment'] = 'The app-id {app_id} will be created.'.format(
                app_id=app_id)
        elif current_id['data']['policies'] != policies:
            ret['changes']['old'] = current_id
            ret['comment'] = ('The app-id {app_id} will have its policies '
                              'updated'.format(app_id=app_id))
    else:
        try:
            new_id = __salt__['vault.create_app_id'](app_id,
                                                     policies,
                                                     display_name,
                                                     mount_point,
                                                     **kwargs)
            ret['result'] = True
            ret['comment'] = ('Successfully created app-id {app_id}'.format(
                app_id=app_id))
            ret['changes'] = {
                'old': current_id,
                'new': __salt__['vault.get_app_id'](app_id, mount_point)
            }
        except __utils__['vault.vault_error']() as e:
            log.exception(e)
            ret['result'] = False
            ret['comment'] = ('Encountered an error while attempting to '
                              'create app id.')
    return ret


def policy_present(name, rules):
    """
    Ensure that the named policy exists and has the defined rules set

    :param name: The name of the policy
    :param rules: The rules to set on the policy
    :returns: The result of the state execution
    :rtype: dict
    """
    current_policy = __salt__['vault.get_policy'](name, parse=True)
    ret = {'name': name,
           'comment': '',
           'result': False,
           'changes': {}}
    if current_policy == rules:
        ret['result'] = True
        ret['comment'] = ('The {policy_name} policy already exists with the '
                          'given rules.'.format(policy_name=name))
    elif __opts__['test']:
        ret['result'] = None
        if current_policy:
            ret['changes']['old'] = current_policy
            ret['changes']['new'] = rules
        ret['comment'] = ('The {policy_name} policy will be {suffix}.'.format(
            policy_name=name,
            suffix='updated' if current_policy else 'created'))
    else:
        try:
            __salt__['vault.set_policy'](name, rules)
            ret['result'] = True
            ret['comment'] = ('The {policy_name} policy was successfully '
                              'created/updated.'.format(policy_name=name))
            ret['changes']['old'] = current_policy
            ret['changes']['new'] = rules
        except __utils__['vault.vault_error']() as e:
            log.exception(e)
            ret['comment'] = ('The {policy_name} policy failed to be '
                              'created/updated'.format(policy_name=name))
    return ret

def policy_absent(name):
    """
    Ensure that the named policy is not present

    :param name: The name of the policy to be deleted
    :returns: The result of the state execution
    :rtype: dict
    """
    current_policy = __salt__['vault.get_policy'](name, parse=True)
    ret = {'name': name,
           'comment': '',
           'result': False,
           'changes': {}}
    if not current_policy:
        ret['result'] = True
        ret['comment'] = ('The {policy_name} policy is not present.'.format(
            policy_name=name))
    elif __opts__['test']:
        ret['result'] = None
        if current_policy:
            ret['changes']['old'] = current_policy
            ret['changes']['new'] = {}
        ret['comment'] = ('The {policy_name} policy {suffix}.'.format(
            policy_name=name,
            suffix='will be deleted' if current_policy else 'is not present'))
    else:
        try:
            __salt__['vault.delete_policy'](name)
            ret['result'] = True
            ret['comment'] = ('The {policy_name} policy was successfully '
                              'deleted.')
            ret['changes']['old'] = current_policy
            ret['changes']['new'] = {}
        except __utils__['vault.vault_error']() as e:
            log.exception(e)
            ret['comment'] = ('The {policy_name} policy failed to be '
                              'created/updated'.format(policy_name=name))
    return ret


def role_present(name, mount_point, options, override=False):
    """
    Ensure that the named role exists. If it does not already exist then it
    will be created with the specified options.

    :param name: The name of the role
    :param mount_point: The mount point of the target backend
    :param options: A dictionary of the configuration options for the role
    :param override: Write the role definition even if there is already one
                     present. Useful if the existing role doesn't match the
                     desired state.
    :returns: Result of executing the state
    :rtype: dict
    """
    current_role = __salt__['vault.read']('{mount}/roles/{name}'.format(
        mount=mount_point, name=name))
    ret = {'name': name,
           'comment': '',
           'result': False,
           'changes': {}}
    if current_role and not override:
        ret['result'] = True
        ret['comment'] = ('The {role} role already exists with the '
                          'given rules.'.format(role=name))
    elif __opts__['test']:
        ret['result'] = None
        if current_role:
            ret['changes']['old'] = current_role
            ret['changes']['new'] = None
        ret['comment'] = ('The {role} role {suffix}.'.format(
            role=name,
            suffix='already exists' if current_role else 'will be created'))
    else:
        try:
            response = __salt__['vault.write']('{mount}/roles/{role}'.format(
                mount=mount_point, role=name), **options)
            ret['result'] = True
            ret['comment'] = ('The {role} role was successfully '
                              'created.'.format(role=name))
            ret['changes']['old'] = current_role
            ret['changes']['new'] = response
        except __utils__['vault.vault_error']() as e:
            log.exception(e)
            ret['comment'] = ('The {role} role failed to be '
                              'created'.format(role=name))
    return ret


def role_absent(name, mount_point):
    """
    Ensure that the named role does not exist.

    :param name: The name of the role to be deleted if present
    :param mount_point: The mount point of the target backend
    :returns: The result of the stae execution
    :rtype: dict
    """
    current_role = __salt__['vault.read']('{mount}/roles/{name}'.format(
        mount=mount_point, name=name))
    ret = {'name': name,
           'comment': '',
           'result': False,
           'changes': {}}
    if current_role:
        ret['changes']['old'] = current_role
        ret['changes']['new'] = None
    else:
        ret['changes'] = None
        ret['result'] = True
    if __opts__['test']:
        ret['result'] = None
        return ret
    try:
        __salt__['vault.delete']('{mount}/roles/{name}'.format(
            mount=mount_point, name=name))
        ret['result'] = True
    except __utils__['vault.vault_error']() as e:
        log.exception(e)
        raise salt.exceptions.SaltInvocationError(e)
    return ret

def ec2_role_created(name,
                     role,
                     bound_ami_id=None,
                     bound_iam_role_arn=None,
                     bound_account_id=None,
                     bound_iam_instance_profile_arn=None,
                     role_tag=None,
                     ttl=None,
                     max_ttl=None,
                     policies=None,
                     allow_instance_migration=False,
                     disallow_reauthentication=False,
                     period="",
                     update_role=False,
                     **kwargs):
    """
    Ensure that the specified EC2 role exists so that it can be used for
    authenticating with the Vault EC2 backend.

    :param name: Contains the id of the state definition
    :param role: The name of the EC2 role
    :param bound_ami_id: The AMI ID to bind the role to
    :param bound_iam_role_arn: The IAM role ARN to bind the Vault EC2 role to
    :param bound_account_id: The account ID to bind the role to
    :param bound_iam_instance_profile_arn: The instance profile ARN to bind the
                                           role to
    :param role_tag: The EC2 tag to use for specifying role access
    :param ttl: The ttl of the credentials granted when authenticating with
                this role
    :param max_ttl: The ttl of the credentials granted when authenticating with
                    this role
    :param policies: The policies to grant on this role
    :param allow_instance_migration: Whether to allow for instance migration
    :param disallow_reauthentication: Whether this role should allow
                                      reauthenticating against Vault
    :returns: The result of the execution
    :rtype: dict
    """
    try:
        current_role = __salt__['vault.get_ec2_role'](role)
    except __utils__['vault.vault_error']():
        current_role = None

    role_params = dict(
        role=role,
        bound_ami_id=bound_ami_id,
        role_tag=role_tag,
        bound_iam_role_arn=bound_iam_role_arn,
        bound_account_id=bound_account_id,
        bound_iam_instance_profile_arn=bound_iam_instance_profile_arn,
        ttl=ttl, max_ttl=max_ttl,
        policies=','.join(policies),
        allow_instance_migration=allow_instance_migration,
        disallow_reauthentication=disallow_reauthentication,
        period=period,
        **kwargs
    )

    current_params = (current_role or {}).get('data', {})

    ret = {'name': name,
           'comment': '',
           'result': False,
           'changes': {}}

    if current_role and not update_role:
        ret['result'] = True
        ret['comment'] = 'The {0} role already exists'.format(role)
    elif __opts__['test']:
        ret['result'] = None
        if current_role:
            ret['comment'] = ('The {0} role will be updated with the given '
                              'parameters').format(role)
            ret['changes']['old'] = current_params
            ret['changes']['new'] = role_params
        else:
            ret['comment'] = ('The {0} role will be created')
    else:
        try:
            __salt__['vault.create_vault_ec2_client_configuration']()
            __salt__['vault.create_ec2_role'](
                **{k: str(v) for k, v in role_params.items() if not v is None})
            ret['result'] = True
            ret['comment'] = 'Successfully created the {0} role.'.format(role)
            ret['changes']['new'] = __salt__['vault.get_ec2_role'](role)
            ret['changes']['old'] = current_role or {}
        except __utils__['vault.vault_error']() as e:
            log.exception(e)
            ret['result'] = False
            ret['comment'] = 'Failed to create the {0} role.'.format(role)
    return ret


def ec2_minion_authenticated(name, role, pkcs7=None, nonce=None,
                             is_master=False, client_conf_files=None):
    """Authenticate a minion using EC2 auth and write the client token to the
    configuration file to be used for subsequent calls to vault.

    :param name: String, unused
    :param role: The role that the minion is to be authenticated against
    :param pkcs7: The pkcs7 key for the minion, will be fetched from EC2
                  metadata if not passed to the function.
    :param nonce: An arbitrary string to be used for future authentication attempts.
                  Will be generated automatically by Vault if not provided.
    :param is_master: Boolean value to determine whether the configuration file
                      needs to be written out for the master as well.
    :param client_conf_file: One or more file paths for where the client token
                             and nonce will be written to.
    :returns: client token and lease information
    :rtype: dict

    """
    # Make sure that the target role exists before trying to use it to auth
    try:
        __salt__['vault.get_ec2_role'](role)
    except hvac.exceptions.Forbidden as e:
        log.info('The configured token is no longer valid. Attempting to '
                 're-authenticate')
    except (hvac.exceptions.InvalidRequest, hvac.exceptions.InvalidPath):
        log.error('Specified EC2 role has not been created.')
        raise
    ret = {
        'name': name,
        'comment': '',
        'result': False,
        'changes': {}
    }
    try:
        is_authenticated = __salt__['vault.is_authenticated']()
    except (hvac.exceptions.InvalidRequest, hvac.exceptions.InvalidPath) as e:
        log.exception(e)
        raise
    if not is_authenticated:
        ret['comment'] = ('The minion will be authenticated to Vault using '
                          'the EC2 authentication backend.')
    else:
        ret['comment'] = ('The minion is already authenticated. No '
                          'action will be performed.')
    if __opts__['test']:
        ret['result'] = None
    else:
        try:
            if not pkcs7:
                pkcs7 = ''.join(
                    __salt__['http.query'](
                        'http://169.254.169.254/latest/dynamic/instance-identity/pkcs7'
                    ).get('body', '').splitlines())
            if not nonce and __salt__['config.get']('vault.nonce'):
                nonce = __salt__['config.get']('vault.nonce')
            auth_result = __salt__['vault.auth_ec2'](pkcs7=pkcs7, role=role,
                                                     nonce=nonce)
            log.debug('Auth response attributes: {}'.format(
                auth_result['auth'].keys()))
            client_config = {
                'vault.{0}'.format(k): v for k, v in auth_result['auth'].items()
            }

            client_config['vault.token'] = client_config.pop('vault.client_token')

            if nonce:
                client_config['vault.nonce'] = nonce

            vault_conf_files = []
            if not client_conf_files:
                vault_conf_files.append(os.path.join(
                    salt.syspaths.CONFIG_DIR,
                    os.path.dirname(__salt__['config.get']('default_include')),
                    '99_vault_client.conf'))
                if is_master:
                    vault_conf_files.append(os.path.join(
                        salt.syspaths.CONFIG_DIR,
                        os.path.dirname(
                            salt.config.apply_master_config(
                                {})['default_include']),
                        '99_vault_client.conf'))
            else:
                if not isinstance(client_conf_files, list):
                    client_conf_files = [client_conf_files]
                vault_conf_files.extend(client_conf_files)
            for fpath in vault_conf_files:
                with open(fpath, 'w') as vault_conf:
                    for k, v in client_config.items():
                        vault_conf.write('{key}: {value}\n'.format(key=k, value=v))
            ret['changes']['new'] = auth_result
            ret['changes']['old'] = {}
            ret['comment'] = 'Successfully authenticated using EC2 backend'
            ret['result'] = True
        except (hvac.exceptions.InvalidRequest, hvac.exceptions.InvalidPath) as e:
            log.exception(e)
            ret['result'] = False
            ret['comment'] = 'Failed to authenticate'
    return ret
