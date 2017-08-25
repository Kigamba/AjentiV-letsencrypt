import pwd
import grp
import os
import subprocess
import json
import traceback

from string import Template
from shutil import copyfile

from ajenti.api import *
from ajenti.plugins.main.api import SectionPlugin
from ajenti.ui import on
from ajenti.ui.binder import Binder
from ajenti.util import platform_select

from pprint import pprint

from os import listdir

from os.path import isfile

currentFolderPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
def log(tolog):
    file = open(currentFolderPath + '/' + "log.txt", 'a')
    file.write('\n' + str(tolog))
    file.close()

class Settings (object):
   def __init__(self):
      self.basedir = platform_select(
          debian='/etc/dehydrated/',
          centos='/etc/dehydrated/',
          mageia='/etc/dehydrated/',
          freebsd='/usr/local/etc/dehydrated/',
          arch='/etc/dehydrated/',
          osx='/opt/local/etc/dehydrated/',
      )

      self.wellknown = '/var/www/dehydrated/'
      self.domains = 'example.com sub.example.com'
      self.cronjob = False
      self.cronfile = 'letsencrypt'
      self.results = ''
      self.domainfile = 'domains.txt'
      self.nginx_config = '00_dehydrated.conf'

@plugin
class LetsEncryptPlugin (SectionPlugin):

    pwd = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
    log("PWD FILE PATH :: " + str(pwd) )

    nginx_config_dir = platform_select(
        debian='/etc/nginx.custom.d',
        centos='/etc/nginx.custom.d',
        mageia='/etc/nginx.custom.d',
        freebsd='/usr/local/etc/nginx.custom.d',
        arch='/etc/nginx/sites-available',
        osx='/opt/local/etc/nginx',
    )

    nginx_hosts_config_dir = platform_select(
        debian='/etc/nginx/conf.d',
        centos='/etc/nginx/conf.d',
        mageia='/etc/nginx/conf.d',
        freebsd='/usr/local/etc/nginx/conf.d',
        arch='/etc/nginx/sites-available',
        osx='/opt/local/etc/nginx',
    )

    crontab_dir = platform_select(
        debian='/etc/cron.d',
        centos='/etc/cron.d',
        mageia='/etc/cron.d',
        freebsd='/usr/local/etc/cron.d',
        arch='/etc/cron.d',
        osx='/opt/local/etc/cron.d',
    )

    has_domains = False

    def init(self):
        self.title = 'LetsEncrypt'  # those are not class attributes and can be only set in or after init()
        self.icon = 'lock'
        self.category = 'Security'

        """
        UI Inflater searches for the named XML layout and inflates it into
        an UIElement object tree
        """
        self.append(self.ui.inflate('letsencrypt:main'))

        self.settings = Settings()

        self.binder = Binder(self.settings, self)
        self.binder.populate()

    def on_page_load(self):
        filepath = self.settings.basedir + self.settings.domainfile
        domains = ''
        if os.path.isfile(filepath):
            domains = os.linesep.join(self.read_domain_file())
        cron = self.check_cron()
        self.find('domains').value = str(domains)
        self.find('cronjob').value = cron

    def write_domain_file(self):
        filepath = self.settings.basedir + self.settings.domainfile
        log("Writing domain file -> [" + filepath + "]")
        if not self.find('domains').value:
            self.context.notify('info', 'No domains specified')
            self.has_domains = False
            log("There are not Domains Specified! Probably in the form request parameters")
            return

        file = open(filepath, 'w')
        if file.write(self.find('domains').value) is None:
            log("Writing to domain file succeeded!")
            self.has_domains = True
        else:
            log("Writing to domain file failed!")
            self.context.notify('error', 'Domain file write error')
        file.close()

    def read_domain_file(self):
        filepath = self.settings.basedir + self.settings.domainfile
        log("Reading domain file [" + filepath + "]")
        if not open(filepath):
            log("Domain file could not be read")
            self.context.notify('error', 'Domain file could not be read')

        file = open(filepath)
        with file as f:
            lines = f.readlines()
        log("Domain file read :: ****\n" + "\n" .join(lines) + "\n****\n")
        return lines

    def create_folders(self):
        log("Creating Folders!")
        uid = pwd.getpwnam("www-data").pw_uid
        gid = grp.getgrnam("www-data").gr_gid

        if not os.path.exists(self.settings.basedir):
            log("Creating Base Directories and owning them to www-data user [" + self.settings.basedir + "]")
            os.makedirs(self.settings.basedir)
            os.chown(self.settings.basedir, uid, gid)
        if not os.path.exists(self.settings.wellknown):
            log("Creating the well-known directories letsencrypt.sh [" + self.settings.wellknown + "] && chowning them to www-data user")
            os.makedirs(self.settings.wellknown)
            os.chown(self.settings.wellknown, uid, gid)

    def create_custom_config(self):
        template = """
        BASEDIR=$basedir
        WELLKNOWN=$wellknown
        """
        dict = {
            'basedir': self.settings.basedir,
            'wellknown': self.settings.wellknown
        }

        log("Creating a custom config!")

        filename = 'config'
        filepath = self.settings.basedir + filename
        log("Custom config Filepath :: " + filepath)
        file = open(filepath, 'w')
        src = Template( template )
        if file.write(src.safe_substitute(dict)) is not None:
            log("Error occured writing Custom Config to file :: " + src.safe_substitute(dict))
            self.context.notify('info', 'Letsencrypt error')
        file.close()

    def create_wellknown(self):
        if not self.check_nginx_custom_dir():
            return False

        template = """
server {
    server_name $domains;
    listen *:80;
    location $location {
        alias $alias;
    }
}
        """
        log("Writing to the nginx config to redirect to the " + self.settings.wellknown)
        dict = {
            'location': '/.well-known/acme-challenge',
            'alias': self.settings.wellknown,
            'domains': " ".join(self.read_domain_file())
        }
        filepath = self.nginx_config_dir + '/' + self.settings.nginx_config
        log("NGINX CONFIG FILE LOCATION [" + filepath + "]")
        file = open(filepath, 'w')
        src = Template( template )
        if file.write(src.safe_substitute(dict)) is not None:
            log("NGINX WRITE CONFIG ERROR TRYING TO WRITE\n*****\n" + src.safe_substitute(dict) + "\n*****\n")
            self.context.notify('info', 'WELLKNOWN config write error')
        else:
            log("NGINX WRITE CONFIG SUCCESS \n*****\n" + src.safe_substitute(dict) + "\n*****\n")
        file.close()

    def create_cron(self):
        file = open(self.crontab_dir + '/' + self.settings.cronfile, 'w')
        template = "0 0 1 * * " + self.pwd + 'libs/dehydrated/dehydrated.sh -c'
        file.write(template)
        log("Creating cron in file [" + (self.crontab_dir + "/" + self.settings.cronfile) + "] with Command [" + template + "]" )
        file.close()

    def remove_cron(self):
        log("Removing cron commands from file " + (self.crontab_dir + '/' + self.settings.cronfile) + " By Deleting It!")
        if os.path.isfile(self.crontab_dir + '/' + self.settings.cronfile):
            if os.remove(self.crontab_dir + '/' + self.settings.cronfile):
                log("Removed the cron file successfully")
                return True
            else:
                log("Removing the cron file unsuccessful")
                self.context.notify('info', 'Cron remove error')
                return False

    def check_cron(self):
        log("Checking if Cron File Exists [" + (self.crontab_dir + '/' + self.settings.cronfile))
        if os.path.isfile(self.crontab_dir + '/' + self.settings.cronfile):
            log("Cron File Exists")
            return True
        log("Cron File Does Not Exist")
        return False

    def check_nginx_custom_dir(self):
        log("Checking if Custom NGINX dir exist!")
        if not os.path.isdir(self.nginx_config_dir):
            if os.makedirs(self.nginx_config_dir):
                return True
            else:
                self.context.notify('error', 'NGINX custom dir write error')
                return False

    def request_certificates(self):
        params = [ "sudo " + self.pwd + 'libs/dehydrated/dehydrated.sh', '-c']
        log("Request certificates with params -> [" + " ".join(params)  + "]")
        """ self.log(params[0]) """
        if self.find('renewal').value:
            log("Renewal TRUE!! Force renewal if already exists")
            params.append('--force')
        else:
            log("Renewal FALSE!! Will not force renewal if the certificates have already been issued")

        try:
            log("Creating a subprocess to perform the command!")
            p = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
        except NameError as ex:
            log("Error Occurred trying to perform the Command")
            log( str(type(ex)) )
            log( str(ex.message) )
            log( str(ex.args) )
            log( str(ex) )
            log( traceback.print_exc() )
            self.context.notify('info', 'An error occured! Please check the logs')
            return

        if out:
            self.context.notify('info', 'OUT: ' + out)
        if err:
            log(err + '')
            self.context.notify('info', 'ERR: ' + err)

    def save(self):
        log("Saving the current urls")
        self.binder.update()
        self.binder.populate()
        self.create_folders()
        self.write_domain_file()

        if not self.has_domains:
            log("No domains to Write!! Returning")
            return

        self.create_custom_config()
        self.create_wellknown()

        if self.settings.cronjob:
            log("CronJob Option TRUE")
            self.create_cron()
        else:
            log("CronJob Option FALSE")
            self.remove_cron()

    @on('save', 'click')
    def save_button(self):
        self.save()

    @on('request', 'click')
    def request_button(self):
        self.save()
        log("Requesting certificates onClick()")
        self.backup_files_add_location_alias()
        self.request_certificates()
        self.restore_backup_conf_files()

    @on('register', 'click')
    def register_click(self):
        self.register_user()

    def register_user(self):
        ''' Register your email here'''
        params = ["sudo " + self.pwd + 'libs/dehydrated/dehydrated.sh', '--register', '--accept--terms']

        try:
            log("Creating a subprocess to perform the command!")
            p = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
        except NameError as ex:
            log("Error Occurred trying to perform the Command")
            log( str(type(ex)) )
            log( str(ex.message) )
            log( str(ex.args) )
            log( str(ex) )
            log( traceback.print_exc() )
            self.context.notify('info', 'An error occured! Please check the logs')
            return

        if out:
            self.context.notify('info', 'OUT: ' + out)
        if err:
            log(err + '')
            self.context.notify('info', 'ERR: ' + err)

    def backup_files_add_location_alias(self):
        ''' Get a list of all files in the nginx/conf.d && make backups of them save the final filenames'''
        self.original_files = []
        count = 0
        location_block = """
    location $location {
        alias $alias;
    }
        """
        location_dict = {
            'location': "/.well-known/acme-challenge",
            'alias': self.settings.wellknown
        }
        src = Template(location_block)
        for f in listdir(self.nginx_hosts_config_dir):
            if isfile(self.nginx_hosts_config_dir + "/" + f):
                self.original_files.append(self.nginx_hosts_config_dir + "/" + f)
                self.create_backup_file(self.original_files[count], ".bkp")
                self.add_location_alias(self.original_files[count], src.safe_substitute(location_dict))
                count += 1
            else:
                log("[" + (self.nginx_hosts_config_dir + "/" + f) + "] is not a file")

    def create_backup_file(self, original_file, suffix):
        file = open(original_file)
        with file as f:
            lines = f.readlines()
        file.close()
        file = open(original_file + suffix, 'w')
        file.write("\n".join(lines))
        file.close()
        return True

    def add_location_alias(self, original_file, location_block):
        file = open(original_file)
        last_closing_braket = 0
        counter = 0

        with file as f:
            lines = f.readlines()
        file.close()
        count = len(lines)

        while counter < count:
            line = lines[counter]
            if line.find("}") > 0:
                last_closing_braket = counter
            counter += 1
        lines.insert(last_closing_braket - 1, location_block)
        file = open(original_file, 'w')
        file.write("\n".join(lines))
        file.close()
        return True

    def read_file(self, file_name):
        file = open(file_name)
        with file as f:
            lines = f.readline
        file.close()
        return "\n".join(lines)


    def restore_backup_conf_files(self):
        for backup_file in self.original_files:
            file_contents = self.read_file(backup_file)
            file = open(backup_file.replace(".bkp", ""), 'w')
            file.write(file_contents)
            file.close()
        log("Finished Restoring the backed up conf files!")




