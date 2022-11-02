# Put a start script in a global location. We tell the user to run 'mailinabox'
# in the first dialog prompt, so we should do this before that starts.
cat > /usr/local/bin/mailinabox << EOF;
#!/bin/bash
cd $(pwd)
source setup/start.sh
EOF
chmod +x /usr/local/bin/mailinabox
