#!/bin/bash

### This is the shell script helps setting the initial environment

# Some tools
sudo apt update
sudo apt install -y gcc gcc-multilib g++ gdb make 
sudo apt install -y manpages-dev manpages-posix manpages-posix-dev 
sudo apt install -y yasm nasm libcapstone-dev curl
sudo apt install -y vim net-tools ssh apt-transport-https


# Install docker
sudo apt install -y docker.io docker-compose


# Install chinese keyboard
sudo apt install -y ibus-chewing # need to reboot


# Close the desktop animation in ubuntu
sudo apt install dbus-x11
sudo gsettings set org.gnome.desktop.interface enable-animations false


# Install vscode
sudo apt install ./<file>.deb
sudo apt-get install -y wget gpg
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
rm -f packages.microsoft.gpg
sudo apt update && sudo apt install -y code


# Install Wine
sudo dpkg --add-architecture i386
sudo mkdir -pm755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key
sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/jammy/winehq-jammy.sources
sudo apt update && sudo apt install -y --install-recommends winehq-stable