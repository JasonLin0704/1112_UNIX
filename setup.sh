#!/bin/bash

# This is the shell script helps setting the initial environment

# Some tools
sudo apt update
sudo apt install -y gcc gcc-multilib g++ gdb make 
sudo apt install -y manpages-dev manpages-posix manpages-posix-dev 
sudo apt install -y yasm nasm libcapstone-dev curl
sudo apt install -y vim net-tools ssh which

# Install docker
sudo apt install -y docker.io docker-compose

# Install chinese keyboard
sudo apt install -y ibus-chewing

# Close the desktop animation of ubuntu 20.04
gsettings set org.gnome.desktop.interface enable-animations false

