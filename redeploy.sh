#/bin/bash
#
__dir__=$(realpath $(dirname $0))
source "${__dir__}/venv/bin/activate"
python -m build
sudo podman build -t 127.0.0.1:5000/localimages/ironic-python-agent .
deactivate
sudo podman push --tls-verify=false 127.0.0.1:5000/localimages/ironic-python-agent
for i in $(seq 9); do
	sudo podman kill "ironic-python-agent-$i" | true
	sudo podman rm "ironic-python-agent-$i" | true
	sudo podman run -d --net host --name "ironic-python-agent-$i" -e IPA_PORT="999${i}" 127.0.0.1:5000/localimages/ironic-python-agent
done
