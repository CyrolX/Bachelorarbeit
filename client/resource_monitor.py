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
            eval_storage,
            printer = print,
            printer_args = [],
            printer_kwargs = {}
            ):
        self.cpu_limit = cpu_limit
        self.ram_limit = ram_limit
        self.eval_storage = eval_storage
        self.monitor_subprocess = None
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
        command = f"\"sudo sh -c 'echo \"+cpu\" >> " \
            "/sys/fs/cgroup/cgroup.subtree_control'\""
        
        self.process_ssh_command(command)


    def set_resource_limits_at_service(self):
        command = f"\"sudo sh -c 'echo \"{self.cpu_limit} 100000\" >> " \
            "/sys/fs/cgroup/eval.slice/cpu.max'\""

        self.process_ssh_command(command)

        real_ram_limit = (self.ram_limit // self._page_size) * self._page_size
        command = f"\"sudo sh -c 'echo \"{real_ram_limit}\" >> " \
            "/sys/fs/cgroup/eval.slice/memory.max'\""
        
        self.process_ssh_command(command)

        command = f"\"sudo sh -c 'echo \"{real_ram_limit}\" >> " \
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
        command = "\"sudo sh -c 'while true; " \
            "do systemd-cgtop --raw --cpu=time | " \
            f"grep eval.slice >> {client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}"\
            "/resource_usage.txt; sleep 1; done'\""
        self.monitor_subprocess = subprocess.Popen(
            f"ssh {client_secrets.CONNECTION} {command}",
            creationflags=subprocess.CREATE_NO_WINDOW
            )


    def terminate_monitor(self):
        if self.monitor_subprocess:
            self.monitor_subprocess.terminate()
            self.monitor_subprocess = None

        # Terminating the subprocess doesn't kill the process at the service
        # which is why we need to kill the shell running the script specified
        # in start_resource_monitoring. Killing the shell kills its associated
        # scripts without any issues.
        command = "\"sudo kill $(pgrep -f 'sudo sh -c while true')\""
        with subprocess.Popen(
            f"ssh {client_secrets.CONNECTION} {command}",
            stdout = subprocess.PIPE, 
            creationflags=subprocess.CREATE_NO_WINDOW
            ) as kill_process:
            try:
                out, err = kill_process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                kill_process.send_signal(signal.CTRL_BREAK_EVENT)
                kill_process.kill()
                out, err = kill_process.communicate()


    def fetch_resource_measurements(
            self, 
            login_method,
            test_length,
            number_of_users_used_in_test
            ):
        # This pattern is used on all local log files to filter out all the
        # log files, who were created during a test using the supplied login
        # method, as well as the supplied number of users and the supplied
        # test length.
        local_record_file_pattern = regex.compile(
            f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}-resmon-" \
            f"{r'-\d+\.txt'}"
            )

        # We want to save our log in the following pattern:

        # {login_method}-eval-{test_length}-{num_users}-{id}.log

        # For this we need to know how many logs, who are using the supplied
        # login method, the supplied number of users and the supplied test_
        # length, already exist, so that we do not overwrite any existing log
        # files.
        id_for_next_record = 1
        for file_name in os.listdir(client_secrets.LOG_STORAGE_PATH):
            if local_record_file_pattern.match(file_name):
                id_for_next_record += 1
        
        local_record_file_name = f"{login_method}-eval-{test_length}-" \
            f"{number_of_users_used_in_test}-resmon-{id_for_next_record}.txt"
        
        path_to_record = "" \
            f"{client_secrets.LOG_STORAGE_PATH}/{local_record_file_name}"

        path_to_record_on_server = ""\
            f"{client_secrets.LOG_STORAGE_PATH_AT_ORIGIN}/resmon.txt"
        subprocess.run(
            [
            "scp", 
            f"{client_secrets.CONNECTION}:{path_to_record_on_server}",
            path_to_record
            ],
        )

        # We return the path to the log here to use it later on.
        return path_to_record


    def stop_resource_monitoring(
            self, 
            login_method,
            test_length,
            number_of_users_used_in_test
            ):
        self.terminate_monitor()
        self.fetch_resource_measurements(
            login_method,
            test_length,
            number_of_users_used_in_test
            )