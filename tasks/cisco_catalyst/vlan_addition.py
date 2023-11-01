import jinja2
from main import ModuleVariables

def main(switch):
    # Define Jinja environment and load templates
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader('tasks/cisco_catalyst/config_templets'),
    )
    template = env.get_template('vlan_addition.j2')

    def set_module_variable(attr):
        if hasattr(ModuleVariables, attr):
            return getattr(ModuleVariables, attr)
        new_value = input(f"Enter {attr.replace('_', ' ').upper()}: ")
        setattr(ModuleVariables, attr, new_value)
        return new_value

    vlan_id = set_module_variable('vlan_id')
    vlan_name = set_module_variable('vlan_name')

    switch.ssh.expect('#')
    switch.ssh.sendline(template.render(vlan_id=vlan_id, vlan_name=vlan_name))
    switch.ssh.expect(['#end'])
