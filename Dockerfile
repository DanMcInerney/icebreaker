FROM phusion/baseimage

# Dat Meta Data Though
LABEL maintainer="@DanMcInerney, @awhitehatter"
LABEL version="1.0"

#Run updates and relevant packages for install (derived from setup.sh)
# No Package for python-backports-shutil-get-terminal-size, install from PIP instead
#RUN apt-get update && apt-get dist-upgrade -y && \
RUN apt-get install python3-dev libxml2-dev libssl-dev tmux python-pip smbclient xterm sudo git python3-pip python3-netifaces -y && \
    pip2 install --upgrade mitm6 pexpect ldap3 backports.shutil_get_terminal_size && \
    pip3 install --upgrade libtmux termcolor requests python-libnmap netaddr && \
    git clone --recursive https://github.com/DanMcInerney/icebreaker.git

# Set the working directory
WORKDIR icebreaker/

# Install submodules - derived from setup.sh
RUN cd submodules/JohnTheRipper/src && ./configure && make && \
    cd ../../impacket/ && python2 setup.py install && \
    cd ../Empire/setup/ && yes | ./install.sh 

ENTRYPOINT [ "/icebreaker/icebreaker.py" ]
CMD [ "--help" ]
