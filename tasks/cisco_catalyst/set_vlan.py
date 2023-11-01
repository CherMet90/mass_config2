import jinja2

from errors import Error, NonCriticalError

def main(switch):
    # Define Jinja environment and load templates
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('tasks/cisco_catalyst/config_templets'),
    )
    template = env.get_template('set_vlan.j2')

    # Задаем вланы в зависимости от площадки
    if switch.site_slug == 'ust':
        vlan_id = '300'
    elif switch.site_slug == 'shb':
        vlan_id = '650'

    # Конфигурация
    switch.ssh.expect('#')
    if switch.interfaces.mode.value == 'access':
        switch.ssh.sendline(template.render(interface=switch.interfaces.name, vlan_id=vlan_id))
    else:
        NonCriticalError(f"Interface {switch.interfaces.name} is not in access mode", switch.ip_address)
        return
    switch.ssh.expect(['#end'])
