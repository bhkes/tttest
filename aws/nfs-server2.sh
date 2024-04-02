#!/bin/bash
mkdir /nfs-shared
echo "/nfs-shared 10.0.0.0/14(rw,sync)" >> /etc/exports
systemctl restart nfs-server
systemctl enable nfs-server
