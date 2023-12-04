import subprocess
import os
import json

OLD_NODE = ".old_node"

def run_baremetal(cmd):
    if len(cmd) == 0 or cmd[0] != "baremetal":
        cmd = ["baremetal"] + cmd
    resp = subprocess.check_output(cmd)
    return resp.decode("utf-8")

def delete_old_node():
    run_baremetal(["node", "delete", "node-new"])

def create_new_node():
    out = run_baremetal(["node", "create", "--name", "node-new", "--driver", "fake-hardware", "-f", "json"])
    data = json.loads(out)
    uuid = data.get("uuid")
    print(uuid)
    with open("node.uuid", "w") as f:
        f.write(uuid)

def generate_ipa():
    pass

if __name__ == "__main__":
    delete_old_node()
    create_new_node()
