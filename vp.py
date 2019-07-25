import yaml
import hvac
import sys
import argparse
from argparse import RawTextHelpFormatter

with open('/etc/vp/config.yml', 'r', encoding='utf8') as f:
  config = yaml.safe_load(f)

client = hvac.Client(url=config['vault']['vault_url'])
client.token = config['vault']['client_token']

def create_update_secret(kvpath, username, kvpass, url):
  dictionary = {'username': username, 'password': kvpass, 'url': url}
  create_response = client.secrets.kv.v2.create_or_update_secret(
    path=kvpath,
    secret=dictionary,
  )

def get_secret(kvpath, kvversion=0, kvkey='all'):
  read_response = client.secrets.kv.v2.read_secret_version(
    path=kvpath,
    version=kvversion,
  )
  if kvkey == 'username':
    if 'username' in read_response['data']['data'].keys():
      print('{val}'.format(val=read_response['data']['data']['username'],))
    else:
      print('No Username for secret {}'.format(kvpath))
  elif kvkey == 'password':
    if 'username' in read_response['data']['data'].keys():
      print('{val}'.format(val=read_response['data']['data']['password'],))
    else:
      print('No Password for secret {}'.format(kvpath))
  elif kvkey == 'url':
    if 'url' in read_response['data']['data'].keys():
      print('{val}'.format(val=read_response['data']['data']['url'],))
    else:
      print('No URL value for secret {}'.format(kvpath))
  else:
    if 'url' in read_response['data']['data'].keys():
      print('Url: {val}'.format(val=read_response['data']['data']['url'],))
    if 'username' in read_response['data']['data'].keys():
      print('Username: {val}'.format(val=read_response['data']['data']['username'],))
    if 'password' in read_response['data']['data'].keys():
      print('Password: {val}'.format(val=read_response['data']['data']['password'],))

def list_versions(secret):
  list_versions = client.secrets.kv.v2.read_secret_version(
    path=secret,
  )
  i = 1
  print('Versions for secret {}:'.format(secret))
  while i < int(list_versions['data']['metadata']['version']):
    current_version = client.secrets.kv.v2.read_secret_version(
      path=secret,
      version=i,
    )
    print('Version: {version} created at {created}'.format(version=current_version['data']['metadata']['version'], created=current_version['data']['metadata']['created_time']))
    i += 1

def list_secrets():
  list_response = client.secrets.kv.v2.list_secrets(path='')
  for key in list_response['data']['keys']:
    print(key)

def delete_secret(secret):
  client.secrets.kv.v2.delete_metadata_and_all_versions(
    path=secret,
  )  

def main():
  parser = argparse.ArgumentParser(description='Vault Password Manager')
  subparsers = parser.add_subparsers(help='sub-command help', dest='subparser_name')
  parser_create = subparsers.add_parser('create', description='Create a new Password.\nExample:\nvp.py create -u testuser -p testpassword [--url https://github.com] -s github', formatter_class=RawTextHelpFormatter)
  parser_create.add_argument('-u', dest='username', required=True, help='Username')
  parser_create.add_argument('-p', dest='password', required=True, help='Password')
  parser_create.add_argument('--url', dest='url', required=False, help='Url password is valued for')
  parser_create.add_argument('-s', dest='secret', required=True, help='Name of the secret for the username/password')
  parser_update = subparsers.add_parser('update', description='Update a password.\nExample:\nvp.py update -u testuser -p testpassword -s github', formatter_class=RawTextHelpFormatter)
  parser_update.add_argument('-u', dest='username', required=False, help='Username')
  parser_update.add_argument('-p', dest='password', required=False, help='Password')
  parser_update.add_argument('--url', dest='url', required=False, help='Url password is valued for')
  parser_update.add_argument('-s', dest='secret', required=True, help='Name of the secret for the username/password')
  parser_get = subparsers.add_parser('get', description='Get password and username.\nExample:\nvp.py get github', formatter_class=RawTextHelpFormatter)
  parser_get.add_argument('secret', help='Name of the secret for the username/password')
  parser_get.add_argument('-t', dest='get_secret', required=False, default='All', help='What type to get password, url, username or all')
  parser_get.add_argument('-v', dest='version', required=False, help='Which version of the secret to get (Use version subcommand to find out which versions exists) default to latest unless set')
  parser_list = subparsers.add_parser('list', description='List existing secrets')
  parser_delete = subparsers.add_parser('delete', description='Delete secret from store')
  parser_delete.add_argument('secret', help='Name of the secret to delete')
  parser_versions = subparsers.add_parser('versions', description='List number of versions for a secret')
  parser_versions.add_argument('secret', help='Name of the secret to lookup versions for')
  args = parser.parse_args()

  if args.subparser_name == 'get':
    get_secret(args.secret, args.version, args.get_secret) 

  if args.subparser_name == 'create':
    create_update_secret(args.secret, args.username, args.password, args.url)

  if args.subparser_name == 'update':
    create_update_secret(args.secret, args.username, args.password, args.url)

  if args.subparser_name == 'list':
    list_secrets()

  if args.subparser_name == 'delete':
    delete_secret(args.secret)

  if args.subparser_name == 'versions':
    list_versions(args.secret)

if __name__ == '__main__':
  main()
