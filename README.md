# certomat
A server to help Unifield instances get certificates

## Setup

  virtualenv venv
  . venv/bin/activate
  # Make this Python able to bind to ports under 1024
  sudo setcap CAP_NET_BIND_SERVICE=+eip venv/bin/python2
  pip install certbot
  # Apply the hack to let it listen on uf6-2.unifield.org only
  patch venv/lib/python2.7/site-packages/certbot/plugins/standalone.py < patch-standalone-ip
  # Register with LetsEncrypt
  certbot register --agree-tos --email jeff.allen@geneva.msf.org --config-dir ./config --work-dir ./work --logs-dir ./logs --non-interactive
