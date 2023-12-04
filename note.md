# Build IPA

```bash
virtualenv venv
source venv/bin/activate
pip install build
python -m build
```

The resulting packages are stored in the `dist` folder.

# Build container

```bash
sudo podman build -t ipa .
```

Run `ironic-python-agent` from inside the container.

# Developing process
- Start the container `sudo podman run --network host -p 9999:9999 -v $PWD:/opt --rm -it localhost/ipa:latest bash`
- Edit the code if needed
- Run `python -m build` to rebuild the package (on the host machine)
- Reinstall the package inside the container `pip3 install dist/ironic_python_agent-8.2.0.dev172-py3-none-any.whl --force-reinstall`
- Create a new node on ironic using `python3 renew_node.py`
- Start fake ipa `ironic-python-agent --api_url http://172.22.0.2:6385 --advertise_host 0.0.0.0 --advertise_port 9999 --listen_port 9999`
