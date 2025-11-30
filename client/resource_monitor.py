import os
import re as regex
from secret import client_secrets
import subprocess
import signal

class ResourceMonitor:
    def __init__(
            self,
            cpu_limit,
            ram_limit,
            idp_cpu_limit,
            idp_ram_limit,
            #eval_storage,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        self.cpu_limit = cpu_limit
        self.ram_limit = ram_limit
        self.idp_cpu_limit = idp_cpu_limit
        self.idp_ram_limit = idp_ram_limit
        #self.eval_storage = eval_storage
        self._monitor_sp_subprocess = None
        self._monitor_idp_subprocess = None
        self._page_size = 4096
        self._idp_page_size = 4096
        self._sp_connection = client_secrets.CONNECTION
        self._idp_connection = client_secrets.IDP_CONNECTION
        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs

##############################################################################
#                               U T I L I T Y                                #
##############################################################################

    def process_ssh_command(self, connection, command):
        with subprocess.Popen(
            f"ssh {connection} {command}",
            stdout = subprocess.PIPE, 
            creationflags=subprocess.CREATE_NO_WINDOW
            ) as process:
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.kill()
                out, err = process.communicate()

##############################################################################
#        R E S O U R C E   M O N I T O R I N G   F O R   T H E   S P         #
##############################################################################

    def shutdown_sp(self):
        command = "" \
            f"\"{client_secrets.SCRIPT_PATH_AT_ORIGIN}/stop_service.sh\""
        
        self.process_ssh_command(self._idp_connection, command)

    
    def start_sp(self):
        command = "" \
            f"\"{client_secrets.SCRIPT_PATH_AT_ORIGIN}/start_service.sh\""
        
        self.process_ssh_command(self._idp_connection, command)


    def enable_cpu_controller(self):
        # These kinds of string hacks must be done, because ssh won't run the
        # the command otherwise.
        # This can be run as often as needed, as echo "+cpu" adds the cpu con-
        # troller to the file. If it is already present, nothing happens.
        command = f"\"sudo sh -c 'echo \"+cpu\" >> " \
            "/sys/fs/cgroup/cgroup.subtree_control'\""
        
        self.process_ssh_command(self._sp_connection, command)

    def enable_cpu_controller(self):
        # This fixes a new problem that has occured. As systemd-cgtop cannot
        # measure I/O-ops without measuring at least twice, I/O-ops need to be
        # read out of the io controller. This isn't enabled by default.
        command = f"\"sudo sh -c 'echo \"+io\" >> " \
            "/sys/fs/cgroup/cgroup.subtree_control'\""
        
        self.process_ssh_command(self._sp_connection, command)


    def convert_cpu_limit_for_sp(self):
        # This also limits the cpu_limit to 5 decimal points, as int() cuts
        # the fractional part of a float.
        return int(self.cpu_limit * 100000)
    

    def convert_ram_limit_for_sp(self):
        # The page size of the used RAM is 4096 Bytes, meaning whenever RAM is
        # assigned it is done in steps of 4096 Bytes. We convert the given RAM
        # limit in Bytes so we only ever assign full pages.
        return (self.ram_limit // self._page_size) * self._page_size


    def set_resource_limits_at_service(self):
        # Limiting resources at the SP is simple, as we just need to write the
        # limits into the respective cgroup controllers
        command = f"\"sudo sh -c 'echo \"{self.convert_cpu_limit_for_sp()} " \
            "100000\" >> /sys/fs/cgroup/eval.slice/cpu.max'\""

        self.process_ssh_command(self._sp_connection, command)

        # We add a page extra here just in case. Killing the process actually
        # isn't the goal, so maybe adding more pages then one here is the
        # better solution.
        command = "\"sudo sh -c " \
            f"'echo \"{self.convert_ram_limit_for_sp() + self._page_size}\"" \
            " >> /sys/fs/cgroup/eval.slice/memory.max'\""
        
        self.process_ssh_command(self._sp_connection, command)

        command = f"\"sudo sh -c 'echo \"{self.convert_ram_limit_for_sp()}\""\
            ">> /sys/fs/cgroup/eval.slice/memory.high'\""
        
        self.process_ssh_command(self._sp_connection, command)


    def reset_resource_limits_at_service(self):
        command = f"\"sudo sh -c 'echo \"max 100000\" >> " \
            "/sys/fs/cgroup/eval.slice/cpu.max'\""
        
        self.process_ssh_command(self._sp_connection, command)

        command = f"\"sudo sh -c 'echo \"max\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.max'\""
        
        self.process_ssh_command(self._sp_connection, command)

        command = f"\"sudo sh -c 'echo \"max\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.high'\""
        
        self.process_ssh_command(self._sp_connection, command)

##############################################################################
#       R E S O U R C E   M O N I T O R I N G   F O R   T H E   I D P        #
##############################################################################

    def shutdown_idp(self):
        command = f"\"{client_secrets.SCRIPT_PATH_AT_IDP}/stop_idp.sh\""
        
        self.process_ssh_command(self._idp_connection, command)

    
    def start_idp(self):
        command = f"\"{client_secrets.SCRIPT_PATH_AT_IDP}/start_idp.sh\""
        
        self.process_ssh_command(self._idp_connection, command)


    def write_container_names_into_idp_record(self, record_path):
        # This utility will help distinguish the data later on.
        command = "\"sudo docker ps --format '{{.ID}} {{.Names}}' >> " \
            f"{record_path}\""
        
        self.process_ssh_command(self._idp_connection, command)


    def convert_ram_limit_for_idp(self):
        # Adding a page extra here just in case.
        real_ram_size = (self.idp_ram_limit // self._idp_page_size) \
            * self._idp_page_size + self._idp_page_size
        # Docker specifically asks for the RAM-limit to be supplied in the
        # format {amount}{byte unit}, with "byte unit" supporting b, k|kb,
        # m|mb and g|gb. The supplied RAM-limit is in bytes, hence the b.
        return f"{real_ram_size}b"
    

    def set_resource_limits_at_idp(self):
        # Limiting resources at the IdP is not as easy as it is for the SP be-
        # cause the relevant processes don't want to be placed into their own
        # cgroup. Instead, the config file of the IdP is edited.
        # Searches for "        restart: true" in the IdP-Config, and appends
        # the memory limits after the line containing this string. This string
        # is confirmed to be unique in the config file.
        # Resource limits are set for Keycloak only, and not for the DB.
        command = "\"sed -i \'/        restart: true/a\\    " \
            "deploy:\\n      resources:\\n        " \
            f"cpus: \"{self.idp_cpu_limit}\"\\n        " \
            f"memory: {self.convert_ram_limit_for_idp()}\' " \
            f"{client_secrets.IDP_CONFIG_PATH}\""
        
        self.process_ssh_command(self._idp_connection, command)


    def reset_resource_limits_at_idp(self):
        # This command finds and removes anything related to resource limiting
        # in the IdP's config. This pattern works, as : is not considerded a
        # "word" character.
        # It has been confirmed, that no other lines contain the listed words
        # so no extra lines can be deleted.
        command = "\"sed -i \'/\\(    \\bdeploy\\b\\|      " \
            "\\bresources\\b\\|        \\bcpus\\b\\|        " \
            f"\\bmemory\\b\\)\\+/d\' {client_secrets.IDP_CONFIG_PATH}\""
        
        self.process_ssh_command(self._idp_connection, command)

##############################################################################
#                                  M A I N                                   #
##############################################################################

    def setup_resource_limits(self):
        self.shutdown_sp()
        self.shutdown_idp()
    
        self.enable_cpu_controller()
        self.set_resource_limits_at_service()
        self.set_resource_limits_at_idp()

        self.start_sp()
        self.start_idp()

    
    def reset_resource_limits(self):
        self.shutdown_sp()
        self.shutdown_idp()

        self.reset_resource_limits_at_service()
        self.reset_resource_limits_at_idp()

        self.start_sp()
        self.start_idp()


    def start_resource_monitoring(self):
        # The Path stays the same at the SP and IdP
        sp_record_path = "" \
            f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/resource_usage.txt"
        idp_record_path = "" \
            f"{client_secrets.LOG_STORAGE_PATH_AT_IDP}/resource_usage.txt"
        
        self.write_container_names_into_idp_record(idp_record_path)
        # Writes a timestamp for the current resource scan in to the record,
        # and then writes the resource scan for the cgroup the nginx and
        # gunicorn processes are in into the record. This is done every second
        # until the monitor is terminated.
        command = "\"sudo sh -c 'while true; " \
            f"do echo -n \"timestamp: \" >> {sp_record_path}; " \
            f"date +%s%N >> {sp_record_path}; "\
            "systemd-cgtop --raw --cpu=time | grep eval.slice >> " \
            f"{sp_record_path}; sleep 1; done'\""
        self._monitor_sp_subprocess = subprocess.Popen(
            f"ssh {self._sp_connection} {command}",
            creationflags=subprocess.CREATE_NO_WINDOW
            )
        
        command = "\"sudo sh -c 'while true; " \
            f"do echo -n \"timestamp: \" >> {idp_record_path}; " \
            f"date +%s%N >> {idp_record_path}; "\
            "systemd-cgtop --raw --cpu=time | grep docker >> " \
            f"{idp_record_path}; sleep 1; done'\""
        self._monitor_idp_subprocess = subprocess.Popen(
            f"ssh {self._idp_connection} {command}",
            creationflags=subprocess.CREATE_NO_WINDOW
            )


    def terminate_monitors(self):
        if self._monitor_sp_subprocess:
            self._monitor_sp_subprocess.terminate()
            self._monitor_sp_subprocess = None
        
        if self._monitor_idp_subprocess:
            self._monitor_idp_subprocess.terminate()
            self._monitor_idp_subprocess = None

        # Terminating the subprocess doesn't kill the process at the service
        # which is why we need to kill the shell running the script specified
        # in start_resource_monitoring. Killing the shell kills its associated
        # scripts without any issues.
        command = "\"sudo kill $(pgrep -f 'sudo sh -c while true')\""

        self.process_ssh_command(self._sp_connection, command)
        self.process_ssh_command(self._idp_connection, command)
