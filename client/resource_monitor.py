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
            #eval_storage,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        self.cpu_limit = cpu_limit
        self.ram_limit = ram_limit
        #self.eval_storage = eval_storage
        self._monitor_subprocess = None
        self._page_size = 4096
        self.printer = printer
        self.printer_args = printer_args
        self.printer_kwargs = printer_kwargs


    def process_ssh_command(self, command):
        with subprocess.Popen(
            f"ssh {client_secrets.CONNECTION} {command}",
            stdout = subprocess.PIPE, 
            creationflags=subprocess.CREATE_NO_WINDOW
            ) as process:
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.send_signal(signal.CTRL_BREAK_EVENT)
                process.kill()
                out, err = process.communicate()


    def enable_cpu_controller(self):
        # These kinds of string hacks must be done, because ssh won't run the
        # the command otherwise.
        # This can be run as often as needed, as echo "+cpu" adds the cpu con-
        # troller to the file. If it is already present, nothing happens.
        command = f"\"sudo sh -c 'echo \"+cpu\" >> " \
            "/sys/fs/cgroup/cgroup.subtree_control'\""
        
        self.process_ssh_command(command)


    def convert_cpu_limit(self):
        # This also limits the cpu_limit to 5 decimal points, as int() cuts
        # the fractional part of a float.
        return int(self.cpu_limit * 100000)
    

    def convert_ram_limit(self):
        # The page size of the used RAM is 4096 Bytes, meaning whenever RAM is
        # assigned it is done in steps of 4096 Bytes. We convert the given RAM
        # limit in Bytes so we only ever assign full pages.
        return (self.ram_limit // self._page_size) * self._page_size


    def set_resource_limits_at_service(self):
        command = f"\"sudo sh -c 'echo \"{self.convert_cpu_limit()} 100000\""\
            " >> /sys/fs/cgroup/eval.slice/cpu.max'\""

        self.process_ssh_command(command)

        # We add a page extra here just in case. Killing the process actually
        # isn't the goal, so maybe adding more pages then one here is the
        # better solution.
        command = "\"sudo sh -c " \
            f"'echo \"{self.convert_ram_limit() + self._page_size}\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.max'\""
        
        self.process_ssh_command(command)

        command = f"\"sudo sh -c 'echo \"{self.convert_ram_limit()}\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.high'\""
        
        self.process_ssh_command(command)


    def reset_resource_limits_at_service(self):
        command = f"\"sudo sh -c 'echo \"max 100000\" >> " \
            "/sys/fs/cgroup/eval.slice/cpu.max'\""
        
        self.process_ssh_command(command)

        command = f"\"sudo sh -c 'echo \"max\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.max'\""
        
        self.process_ssh_command(command)

        command = f"\"sudo sh -c 'echo \"max\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.high'\""
        
        self.process_ssh_command(command)


    def start_resource_monitoring(self):
        # Setup
        self.enable_cpu_controller()
        self.set_resource_limits_at_service()
    
        record_path = "" \
            f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/resource_usage.txt"
        # Writes a timestamp for the current resource scan in to the record,
        # and then writes the resource scan for the cgroup the nginx and
        # gunicorn processes are in into the record. This is done every second
        # until the monitor is terminated.
        command = "\"sudo sh -c 'while true; " \
            f"do echo -n \"timestamp:\" >> {record_path}; " \
            f"date +%s%N >> {record_path}; "\
            "systemd-cgtop --raw --cpu=time | grep eval.slice >> " \
            f"{record_path}; sleep 1; done'\""
        self._monitor_subprocess = subprocess.Popen(
            f"ssh {client_secrets.CONNECTION} {command}",
            creationflags=subprocess.CREATE_NO_WINDOW
            )


    def terminate_monitor(self):
        if self._monitor_subprocess:
            self._monitor_subprocess.terminate()
            self._monitor_subprocess = None

        # Terminating the subprocess doesn't kill the process at the service
        # which is why we need to kill the shell running the script specified
        # in start_resource_monitoring. Killing the shell kills its associated
        # scripts without any issues.
        command = "\"sudo kill $(pgrep -f 'sudo sh -c while true')\""

        self.process_ssh_command(command)
