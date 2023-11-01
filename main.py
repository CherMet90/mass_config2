import getpass
import re
import sys
import importlib.util
import os

import jinja2
import pexpect

from netbox import NetboxDevice
from errors import Error, NonCriticalError
from log import logger
from prettytable import PrettyTable


class ModuleVariables:
    pass


class Family:
    def __init__(self, name, models_line):
        self.name = name
        self.models = list(filter(None, models_line.rstrip().split(',')))


class Switch:
    username = None
    password = None
    ssh_options = '-c aes128-cbc,aes128-ctr -oKexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256 -oStrictHostKeyChecking=accept-new  -oHostKeyAlgorithms=ssh-rsa,ssh-dss'
    families = []  # list of family objects
    # Объявление окружения Jinja и загрузка шаблонов
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('./templates'),
    )
    port_lock_dict = {}

    @classmethod
    def set_login(cls):
        cls.username = input("Enter your username: ")

    @classmethod
    def set_password(cls):
        cls.password = getpass.getpass("Enter your password: ")

    @classmethod
    def load_models(cls, file_name):
        with open(file_name, 'r') as f:
            for line in f:
                model_type, models_line = line.split(':')
                family = Family(model_type, models_line)
                cls.families.append(family)

    def __find_family(self):
        for family in self.families:
            for model in family.models:
                if model == self.model:
                    return family.name
        raise Error(
            f"The model family for {self.model} is not defined.", ip=self.ip_address)

    def __init__(self, ip, model):
        self.ip_address = ip
        self.model = model
        self.model_family = self.__find_family()

        try:
            logger.info(f'Connecting to {self.ip_address}...')
            self.ssh = pexpect.spawn(
                'ssh {} {}@{}'.format(self.ssh_options, self.username, self.ip_address), timeout=15)
            self.ssh.expect('assword:')
            self.ssh.sendline(self.password)
            logger.info('The SSH session has been established.')
            self.ssh.logfile = sys.stdout.buffer
        except pexpect.exceptions.EOF as e:
            msg = "End of File Exception occurred"
            raise Error(msg, ip=self.ip_address)
        except pexpect.exceptions.TIMEOUT as e:
            msg = f"Timeout exceeded"
            raise Error(msg, ip=self.ip_address)
        except pexpect.exceptions.ExceptionPexpect as e:
            msg = f"Unexpected pexpect exception occurred"
            raise Error(msg, ip=self.ip_address, is_critical=False)

        self.ssh.expect(['#', '>', 'Layer 2 Managed Switch', 'Zyxel'])
        if self.model_family == 'cisco_catalyst':
            self.ssh.sendline('terminal length 0')

    # ---------------------------------------------------------------------------------------------------------------
    #   Deprecated
    # ---------------------------------------------------------------------------------------------------------------
    def check_conditions(self):
        # Словарь шаблонов устройств
        CHECK_COMMANDS = {
            'cisco_catalyst': 'shr_cat.j2',
        }
        CONFIGURE_COMMANDS = {
            'cisco_catalyst': ['portlock_update_cat.j2', 'portlock_clean_cat.j2'],
        }

        if self.model_family in CHECK_COMMANDS:
            check_template = self.env.get_template(
                CHECK_COMMANDS[self.model_family])
            config_update_template, config_clean_template = [
                self.env.get_template(template) for template in CONFIGURE_COMMANDS[self.model_family]
            ]
            self.ssh.expect(['#', ']'])
            for interface in self.interfaces:
                if interface.type.value == '1000base-t' and interface.mode.value == 'access':
                    self.ssh.sendline(
                        check_template.render(interface=interface))
                    port_lock_status = self.ssh.expect(
                        ['security mac-address sticky', 'end'])
                    if port_lock_status == 0:
                        self.ssh.expect('end')
                        output = self.ssh.before.decode('utf-8')
                        pattern = re.compile(
                            r'(switchport port-security mac-address sticky .*)')
                        matches = pattern.findall(output)
                        # self.port_lock_dict[interface] = matches
                        self.ssh.sendline(
                            config_update_template.render(interface=interface, matches=matches))
                        self.ssh.expect(['#end'])
                    if port_lock_status == 1:
                        self.ssh.sendline(
                            config_clean_template.render(interface=interface))
                        self.ssh.expect(['#end'])
    # ---------------------------------------------------------------------------------------------------------------
    
    def save(self):
        SAVE_COMMANDS = {
            'cisco_catalyst': 'wr',
            'cisco_sg_350': 'wr',
            'cisco_sg_300': 'wr',
        }

        if self.model_family in SAVE_COMMANDS:
            self.ssh.sendline(SAVE_COMMANDS[self.model_family])
            checkStatus = self.ssh.expect(
                ['Building configuration...', '(Y/N)', '[Y/N]'])
            if checkStatus == 1:  # SG
                self.ssh.sendline('y')
                self.ssh.expect('#')
            elif checkStatus == 2:  # Huawei
                self.ssh.sendline('y')
                self.ssh.expect('>')

if __name__ == '__main__':
    cwd = os.getcwd()   # Get the current working directory
    
    NETBOX_DEVICE_ROLE = {
        'router': 1,
        'ap': 2,
        'wlan-controller': 3,
        'access-switch': 4,
        'poe-switch': 5,
        'aggregation-switch': 6,
        'l3-switch': 7,
        'server-switch': 8,
        'bench-equipment': 9,
        'asu-switch': 10,
        'host': 11
    }
    module_name = input(
        "Enter module name (with file extension): "
    )
    
    # Глобальная конфигурация скрипта
    script_configuration = {
        'searching_by_what': 'role',
        'use_ip_list': False,
        'get_interfaces': 'all',
    }
    print('--- Configuration ---')
    for key, value in script_configuration.items():
        print(f'{key}: {value}')
    input('Correct?')
    
    try:
        if script_configuration['use_ip_list']:
            ### Получение списка ip из файла
            ips = []
            with open('ip.list', 'r') as f:
                for line in f:
                    ips.append(line.strip())
            
        NetboxDevice.create_connection()
        match script_configuration['searching_by_what']:
            case 'role':
                ### Получение списка устройств по роли
                required_role = input("Enter required role ({}): ".format(
                    ", ".join(NETBOX_DEVICE_ROLE.keys())))
                netbox_devices = NetboxDevice.get_devices_by_role(
                    site_slug='ust', role=NETBOX_DEVICE_ROLE[required_role])
            case 'hosts':
                ### Получение списка свичей по ip хостов
                netbox_devices = NetboxDevice.get_interfaces_by_hosts(ips)

        Switch.load_models('models.list')
        Switch.set_login()
        Switch.set_password()

        first_iteration = True
        for key, value in netbox_devices.items():
            try:
                netbox_device = NetboxDevice(key)
                host_interface = value

                switch = Switch(netbox_device.ip_address,
                                netbox_device.role.model)
                switch.site_slug = netbox_device.site.slug
                
                # Получение интерфейсов
                match script_configuration['get_interfaces']:
                    case 'all':
                        switch.interfaces = netbox_device.get_interfaces()
                    case 'by_neighbor_name':
                        switch.interfaces = netbox_device.get_interfaces(host_interface.link_peers[0].name)

                # Динамический импорт требуемого модуля
                spec = importlib.util.spec_from_file_location(
                    "dyn_module", os.path.join(cwd, "tasks", switch.model_family, module_name)
                )
                dyn_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(dyn_module)
                dyn_module.main(switch)

                switch.save()
                switch.ssh.close()
                print('')
                logger.info(f'The connection closed')
                
                if first_iteration:
                    input(f'\nContinue?')
                    first_iteration = False

            except Error:
                continue
    except Error as e:
        pass

    # ВЫВОД ОШИБОК
    # ========================================================================
    # Merge the error messages into a single list
    all_error_messages = Error.error_messages + NonCriticalError.error_messages

    # Flatten the list of dictionaries into a single dictionary
    merged_error_messages = {
        k: v for d in all_error_messages for k, v in d.items()}

    # Print errors in a PrettyTable
    if merged_error_messages:
        table = PrettyTable(["IP", "Error"])
        table.align["IP"] = "l"
        table.align["Error"] = "l"
        table.max_width = 75
        table.valign["Error"] = "t"
        for ip, error_message in merged_error_messages.items():
            table.add_row([ip, error_message])
        logger.info(f'The work is completed.\n{table}')
