from ironic_python_agent.api import app
from ironic_python_agent.extensions import base
from oslo_config import cfg
from oslo_log import log
import eventlet
import _thread

LOG = log.getLogger(__name__)

class FakeIPAServer(base.ExecuteCommandMixin):
    def __init__(self, api_url, advertise_address, listen_address,
                 ip_lookup_attempts, ip_lookup_sleep, network_interface,
                 lookup_timeout, lookup_interval, standalone, agent_token,
                 hardware_initialization_delay=0, advertise_protocol='http'):
        super().__init__()
        self.api = app.Application(self, cfg.CONF)
        self.ext_mgr = base.init_ext_manager(self)
        self._ipa = {}
        self.api_url = api_url
        self.advertise_address = advertise_address
        self.listen_address = listen_address
        self.ip_lookup_attempts = ip_lookup_attempts
        self.ip_lookup_sleep = ip_lookup_sleep
        self.network_interface = network_interface
        self.lookup_timeout = lookup_timeout
        self.lookup_interval = lookup_interval
        self.standalone = standalone
        # agent_token = str('0123456789' * 10)
        # self.agent_token = agent_token
        # self.agent_token_required = cfg.CONF.agent_token_required
        self.hardware_initialization_delay = hardware_initialization_delay
        self.advertise_protocol = advertise_protocol
        # self.api_client = ironic_api_client.APIClient(self.api_url)
        self.serve_api = True
        # self.api = app.Application(self, cfg.CONF)
        # self.api_client = None
        # self.heartbeater = agent.IronicPythonAgentHeartbeater(self)
        self.version = "1.0"
        # self.heartbeat_timeout = 200
        # self.generated_cert = None

    def new_node(self, node_uuid):
        LOG.info('Creating new node, UUID is %s', node_uuid)
        agent_token = "".join([random.randint(0, 10) for _ in range(100)])
        new_ipa = FakeIPA(self.api_url, \
                          self.advertise_address, \
                          self.listen_address, \
                          self.ip_lookup_sleep, \
                          self.ip_lookup_sleep, \
                          self.network_interface, \
                          self.lookup_timeout, \
                          self.lookup_interval, \
                          self.standalone, \
                          agent_token)
        _thread.start_new_thread(new_ipa.start, ())
                          
    def run(self):
        self.serve_ipa_api()

    def serve_ipa_api(self):
        """Serve the API until an extension terminates it."""
        # cert_file, key_file = self._start_auto_tls()
        self.api.start()
        try:
            while self.serve_api:
                eventlet.sleep(0.1)
        except KeyboardInterrupt:
            LOG.info('Caught keyboard interrupt, exiting')
        self.api.stop()

    def validate_agent_token(self, token):
        return True
