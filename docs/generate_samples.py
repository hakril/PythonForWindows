import os
import sys
import subprocess

print(__file__)

samplepath = os.path.join(os.path.dirname(__file__), "..", "samples")
resultdir = os.path.join(os.path.dirname(__file__), "source", "samples_output")
resultdir = os.path.abspath(resultdir)
os.chdir(samplepath)

python_exe = sys.executable

def generate_output_result(target, output):
    print("Generating result of <{0}>".format(target))
    p = subprocess.Popen([python_exe, target], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    result = p.communicate()
    with open(os.path.join(resultdir, output), "wb") as f:
        f.write("(cmd) python {0}\n".format(target))
        f.write(result[0])


if "-n" in sys.argv:
    sys.exit(0)

generate_output_result(r"process\current_process.py", "process_current_process.txt")
generate_output_result(r"process\remote_process.py", "process_remote_process.txt")
generate_output_result(r"process\peb.py", "process_peb.txt")
generate_output_result(r"process\iat_hook.py", "process_iat_hook.txt")
generate_output_result(r"process\veh_segv.py", "process_veh_segv.txt")
generate_output_result(r"process\apisetmap.py", "process_apisetmap.txt")


generate_output_result(r"token\token_demo.py", "token_token_demo.txt")

generate_output_result(r"system.py", "system.txt")
# Require admin for 'network.py'
# Also require a local connection to port 80
generate_output_result(r"network\network.py", "network_network.txt")

# Need to anonymise the output
# generate_output_result(r"registry\registry.py", "registry_registry.txt")

generate_output_result(r"crypto\wintrust.py", "crypto_wintrust.txt")


generate_output_result(r"debug\debugger_print_LdrLoaddll.py", "debug_debugger_print_LdrLoaddll.txt")
generate_output_result(r"debug\debugger_membp_singlestep.py", "debug_debugger_membp_singlestep.txt")
generate_output_result(r"debug\debug_functionbp.py", "debug_debug_functionbp.txt")
generate_output_result(r"debug\attach.py", "debug_attach.txt")
generate_output_result(r"debug\local_debugger.py", "debug_local_debugger.txt")
generate_output_result(r"debug\debugger_on_setup.py", "debug_debugger_on_setup.txt")

# dbg.symbols
generate_output_result(r"debug\symbols\virtsymdemo.py", "debug_symbol_virtsymdemo.txt")
generate_output_result(r"debug\symbols\processsymdemo.py", "debug_symbol_processsymdemo.txt")
generate_output_result(r"debug\symbol_debugger.py", "debug_symbol_debugger.txt")


# Not generated: need parameters
# generate_output_result(r"debug\symbols\symsearch.py", "debug_symbol_symsearch.txt")





generate_output_result(r"wmi\wmi_request.py", "wmi_wmi_request.txt")
generate_output_result(r"wmi\create_process.py", "wmi_create_process.txt")

generate_output_result(r"com\com_inetfwpolicy2.py", "com_com_inetfwpolicy2.txt")
generate_output_result(r"com\icallinterceptor.py", "com_icallinterceptor.txt")

generate_output_result(r"crypto\certificate.py", "crypto_certificate.txt")

# Those 2 create another process: cannot get full output with this simple implem
# generate_output_result(r"alpc\simple_alpc.py", "alpc_simple_alpc.txt")
# generate_output_result(r"alpc\advanced_alpc.py", "alpc_advanced_alpc.txt")

generate_output_result(r"rpc\lsass.py", "rpc_lsass.txt")

generate_output_result(r"pipe\child_send_object.py", "pipe_child_send_object.txt")

generate_output_result(r"scheduled_tasks\scheduled_task.py", "scheduled_task_scheduled_task.txt")
generate_output_result(r"event_log\eventlog.py", "event_log_eventlog.txt")

generate_output_result(r"object_manager\findobj.py", "object_manager_findobj.txt")
generate_output_result(r"object_manager\object_manager.py", "object_manager_object_manager.txt")

generate_output_result(r"security\security_descriptor.py", "security_security_descriptor.txt")


generate_output_result(r"service\service_demo.py", "service_service_demo.txt")

generate_output_result(r"device_manager\device_manager.py", "device_manager_device_manager.txt")


# Require ADMIN / NotAdmin run
# generate_output_result(r"security\query_sacl.py", "security_query_sacl.txt")