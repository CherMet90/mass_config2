import inspect
import os
import traceback

import pynetbox
from colorama import init

from errors import Error, NonCriticalError
from log import logger

# Initialize Colorama
init()


class NetboxDevice:
    # Получение переменных окружения
    # =====================================================================
    @staticmethod
    def __get_env_variable(variable_key):
        variable_value = os.environ.get(variable_key)
        if variable_value is None:
            raise ValueError(f"Missing environment variable: {variable_key}")
        return variable_value

    __netbox_url = __get_env_variable("NETBOX_URL")
    __netbox_token = __get_env_variable("NETBOX_TOKEN")
    # ====================================================================

    # Создание netbox соединения
    @classmethod
    def create_connection(cls):
        try:
            cls.__netbox_connection = pynetbox.api(
                url=cls.__netbox_url,
                token=cls.__netbox_token
            )
            logger.debug("Connection to NetBox established")
        except Exception as e:
            traceback.print_exc()
            raise e

    @classmethod
    def get_devices_by_role(cls, site_slug, role):
        try:
            devices = cls.__netbox_connection.dcim.devices.filter(site=site_slug, role_id=role)
            logger.debug(f"Found {len(devices)} devices for site {site_slug}")
            return {device: None for device in devices}
        except pynetbox.core.query.RequestError as e:
            error_message = f"Request failed for site {site_slug}"
            calling_function = inspect.stack()[1].function
            raise Error(error_message, site_slug, calling_function)
    
    @classmethod
    def get_interfaces_by_hosts(cls, ip_list):
        netbox_devices_and_interfaces = {}
        for ip in ip_list:
            logger.info(f"Getting info for host {ip}")
            # Получаем объект ip-адреса из netbox
            netbox_ip = cls.__netbox_connection.ipam.ip_addresses.get(address=ip)
            if not netbox_ip:
                NonCriticalError(f"IP {ip} not found in NetBox", ip)
                continue
            # Получаем объект интерфейса, ассоциированного с ip-адресом
            if not netbox_ip.assigned_object:
                NonCriticalError(f'IP {ip} has no assigned object', ip)
                continue
            netbox_interface = cls.__netbox_connection.dcim.interfaces.get(id=netbox_ip.assigned_object.id)
            if len(netbox_interface.link_peers) == 0:
                NonCriticalError(f"IP {ip} has no link peers", ip)
                continue
            # Получаем объект устройства, которому принадлежит интерфейс
            netbox_device = cls.__netbox_connection.dcim.devices.get(
                id=netbox_interface.connected_endpoints[0].device.id
            )
            # Вносим информацию в словарь
            netbox_devices_and_interfaces[netbox_device] = netbox_interface
        return netbox_devices_and_interfaces
    
    # # Получение вланов сайта из netbox
    # @classmethod
    # def get_vlans(cls, site_slug):
    #     try:
    #         vlans = list(
    #             cls.__netbox_connection.ipam.vlans.filter(site=site_slug))
    #         # Extract VLAN IDs from the objects
    #         vlan_ids = [str(vlan.vid) for vlan in vlans]
    #         logger.debug(f"Found {len(vlan_ids)} VLANs for site {site_slug}")
    #         return vlans
    #     except pynetbox.core.query.RequestError as e:
    #         error_message = f"Request failed for site {site_slug}"
    #         calling_function = inspect.stack()[1].function
    #         NonCriticalError(error_message, site_slug, calling_function)
    #         return None

    # Создаем экземпляр устройства netbox
    def __init__(self, device):
        self.__netbox_device = device
        self.ip_address = device.primary_ip.address.split('/')[0]
        self.role = device.device_type
        self.site = device.site

    def get_interfaces(self, name=None):
        if name:
            return self.__netbox_connection.dcim.interfaces.get(
                device=self.__netbox_device.name, name=name
            )
        return self.__netbox_connection.dcim.interfaces.filter(
            device=self.__netbox_device.name
        )
    
    # def __get_netbox_device(self):
    #     device = self.__netbox_connection.dcim.devices.get(
    #         name=self.__hostname, site=self.__site_slug)
    #     if not device:
    #         device = self.__netbox_connection.dcim.virtual_chassis.get(
    #             name=self.__hostname, site=self.__site_slug)
    #     return device
    
    # def __check_serial_number(self):
    #     if self.__serial_number and self.__netbox_device.serial != self.__serial_number:
    #         # error_msg = f"Serial number of the device {self.__hostname} ({self.__serial_number}) does not match the serial number of the device in NetBox ({self.__netbox_device.serial})."
    #         # raise Error(error_msg)
    #         self.__netbox_device.serial = self.__serial_number
    #         self.__netbox_device.save()
    #         NonCriticalError(
    #             f'Serial number was changed to {self.__serial_number}', self.__ip_address)

    # def __create_device(self):
    #     def critical_error_not_found(item_type, item_value):
    #         error_msg = f"{item_type} {item_value} not found in NetBox."
    #         raise Error(error_msg)

    #     logger.debug("Creating device...")

    #     self.__netbox_device_type = self.__netbox_connection.dcim.device_types.get(
    #         model=self.__model)
    #     if not self.__netbox_device_type:
    #         critical_error_not_found("device type", self.__model)

    #     self.__netbox_site = self.__netbox_connection.dcim.sites.get(
    #         slug=self.__site_slug)
    #     if not self.__netbox_site:
    #         critical_error_not_found("site", self.__site_slug)

    #     self.__netbox_device_role = self.__netbox_connection.dcim.device_roles.get(
    #         name=self.__role)
    #     if not self.__netbox_device_role:
    #         critical_error_not_found("device role", self.__role)

    #     # Создаем устройство в NetBox
    #     self.__netbox_device = self.__netbox_connection.dcim.devices.create(
    #         name=self.__hostname,
    #         device_type=self.__netbox_device_type.id,
    #         site=self.__netbox_site.id,
    #         device_role=self.__netbox_device_role.id,
    #         status="active",
    #     )
    #     # Костыль на случай отсутствия серийного номера
    #     if self.__serial_number:
    #         self.__netbox_device.serial = self.__serial_number
    #         self.__netbox_device.save()

    #     logger.debug("Device created")

    # def add_interface(self, interface):
    #     # Поиск netbox-объекта влана по VLAN ID
    #     def find_vlan_object(vlan_id):
    #         for vlan in self.__vlans:
    #             if str(vlan.vid) == vlan_id:
    #                 return vlan

    #     def update_interface_fields(netbox_interface, interface_object):
    #         update_fields = ['name', 'mtu', 'mac', "description", 'mode']
    #         for field in update_fields:
    #             if hasattr(interface_object, field):
    #                 setattr(netbox_interface, field,
    #                         getattr(interface_object, field))

    #         netbox_interface.untagged_vlan = find_vlan_object(
    #             interface_object.untagged)
    #         netbox_interface.tagged_vlans = [vlan_obj for vlan_id in interface_object.tagged or [
    #         ] if (vlan_obj := find_vlan_object(vlan_id)) is not None]
    #         netbox_interface.save()

    #     # Проверка существования интерфейса в NetBox
    #     logger.debug(
    #         f"Checking if interface {interface.name} already exists in NetBox...")
    #     existing_interface = self.__netbox_connection.dcim.interfaces.get(
    #         name=interface.name, device=self.__netbox_device.name
    #     )

    #     if existing_interface:
    #         logger.debug(f"Interface {interface.name} already exists")
    #         self.__netbox_interface = existing_interface
    #     else:
    #         logger.debug(f"Creating interface {interface.name}...")
    #         self.__netbox_interface = self.__netbox_connection.dcim.interfaces.create(
    #             name=interface.name,
    #             device=self.__netbox_device.id,
    #             type=getattr(interface, 'type', 'other'),
    #         )
    #     update_interface_fields(self.__netbox_interface, interface)

    #     # Проверка наличия у интерфейса IP-адреса
    #     if hasattr(interface, 'ip_with_prefix'):
    #         logger.debug(f"Interface {interface.name} has IP address")
    #         self.__create_ip_address(interface)

    # def __create_ip_address(self, interface):
    #     # Проверка существования IP-адреса в NetBox
    #     logger.debug(
    #         f"Checking if IP address {interface.ip_with_prefix} already exists in NetBox...")
    #     existing_ip = self.__netbox_connection.ipam.ip_addresses.get(
    #         address=interface.ip_with_prefix
    #     )

    #     if existing_ip:
    #         logger.debug(
    #             f"IP address {interface.ip_with_prefix} already exists")
    #         existing_ip.assigned_object_type = "dcim.interface"
    #         existing_ip.assigned_object_id = self.__netbox_interface.id
    #         existing_ip.save()
    #     else:
    #         logger.debug(f"Creating IP address {interface.ip_with_prefix}...")
    #         existing_ip = self.__netbox_connection.ipam.ip_addresses.create(
    #             address=interface.ip_with_prefix,
    #             status="active",
    #             assigned_object_type="dcim.interface",
    #             assigned_object_id=self.__netbox_interface.id,
    #         )

    #     # Проверка необходимости назначения IP-адреса основным
    #     if interface.ip_address == self.__ip_address:
    #         if str(self.__netbox_device.primary_ip4) != interface.ip_with_prefix:
    #             logger.debug(
    #                 f"Setting {interface.ip_address} as primary IP address")
    #             self.__netbox_device.primary_ip4 = {
    #                 'address': interface.ip_with_prefix}
    #             self.__netbox_device.save()

    # def connect_endpoint(self, parent_device, interface):
    #     def recreate_cable():
    #         logger.debug(f'Deleting the cable...')
    #         self.__netbox_interface.cable.delete()
    #         create_cable()

    #     def create_cable():
    #         logger.debug(f'Creating the cable...')
    #         self.__netbox_interface.cable = self.__netbox_connection.dcim.cables.create(
    #             a_terminations=[{
    #                 "object_id": self.__netbox_interface.id,
    #                 "object_type": 'dcim.interface',
    #             }],
    #             b_terminations=[{
    #                 "object_id": parent_interface.id,
    #                 "object_type": 'dcim.interface',
    #             }]
    #         )
    #         logger.debug(f'The cable has been created')

    #     # Netbox-объект интерфейса свича
    #     parent_interface = self.__netbox_connection.dcim.interfaces.get(
    #         name=interface.name,
    #         device=parent_device.hostname,
    #     )
    #     logger.debug(
    #         f"Checking if cable between {parent_device.hostname} and {self.__netbox_device.name} exists...")
    #     # Если интерфейса хоста нет кабеля - создаем кабель между интерфейсами свича и хостом
    #     if not self.__netbox_interface.cable:
    #         create_cable()
    #     # Если кабель существует, проверяем что он включен в соответсвующий порт свича
    #     else:
    #         logger.debug(f'The cable already exists')
    #         if self.__netbox_interface.connected_endpoints:
    #             for endpoint in self.__netbox_interface.connected_endpoints:
    #                 # Если кабель включен в другой порт - удаляем, создаем новый
    #                 if endpoint.id != parent_interface.id:
    #                     NonCriticalError(
    #                         f'Кабель включен в другой порт ({endpoint.device} {endpoint})'
    #                     )
    #                     recreate_cable()
    #         else:
    #             recreate_cable()
