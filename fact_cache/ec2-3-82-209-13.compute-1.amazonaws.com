{
    "_ansible_facts_gathered": true, 
    "ansible_all_ipv4_addresses": [
        "172.31.81.127"
    ], 
    "ansible_all_ipv6_addresses": [
        "fe80::1058:63ff:fed8:cfd9"
    ], 
    "ansible_apparmor": {
        "status": "disabled"
    }, 
    "ansible_architecture": "x86_64", 
    "ansible_bios_date": "10/16/2017", 
    "ansible_bios_vendor": "Amazon EC2", 
    "ansible_bios_version": "1.0", 
    "ansible_board_asset_tag": "i-06cdb8da4a78f8629", 
    "ansible_board_name": "NA", 
    "ansible_board_serial": "NA", 
    "ansible_board_vendor": "Amazon EC2", 
    "ansible_board_version": "NA", 
    "ansible_chassis_asset_tag": "Amazon EC2", 
    "ansible_chassis_serial": "NA", 
    "ansible_chassis_vendor": "Amazon EC2", 
    "ansible_chassis_version": "NA", 
    "ansible_cmdline": {
        "BOOT_IMAGE": "/boot/vmlinuz-5.10.178-162.673.amzn2.x86_64", 
        "biosdevname": "0", 
        "console": "ttyS0,115200n8", 
        "net.ifnames": "0", 
        "nvme_core.io_timeout": "4294967295", 
        "rd.emergency": "poweroff", 
        "rd.shell": "0", 
        "ro": true, 
        "root": "UUID=902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
    }, 
    "ansible_date_time": {
        "date": "2023-05-18", 
        "day": "18", 
        "epoch": "1684418259", 
        "hour": "13", 
        "iso8601": "2023-05-18T13:57:39Z", 
        "iso8601_basic": "20230518T135739101330", 
        "iso8601_basic_short": "20230518T135739", 
        "iso8601_micro": "2023-05-18T13:57:39.101330Z", 
        "minute": "57", 
        "month": "05", 
        "second": "39", 
        "time": "13:57:39", 
        "tz": "UTC", 
        "tz_dst": "UTC", 
        "tz_offset": "+0000", 
        "weekday": "Thursday", 
        "weekday_number": "4", 
        "weeknumber": "20", 
        "year": "2023"
    }, 
    "ansible_default_ipv4": {
        "address": "172.31.81.127", 
        "alias": "eth0", 
        "broadcast": "172.31.95.255", 
        "gateway": "172.31.80.1", 
        "interface": "eth0", 
        "macaddress": "12:58:63:d8:cf:d9", 
        "mtu": 9001, 
        "netmask": "255.255.240.0", 
        "network": "172.31.80.0", 
        "type": "ether"
    }, 
    "ansible_default_ipv6": {}, 
    "ansible_device_links": {
        "ids": {
            "nvme0n1": [
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f", 
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1", 
                "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001"
            ], 
            "nvme0n1p1": [
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1-part1", 
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-part1", 
                "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001-part1"
            ], 
            "nvme0n1p128": [
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1-part128", 
                "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-part128", 
                "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001-part128"
            ]
        }, 
        "labels": {
            "nvme0n1p1": [
                "\\x2f"
            ]
        }, 
        "masters": {}, 
        "uuids": {
            "nvme0n1p1": [
                "902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
            ]
        }
    }, 
    "ansible_devices": {
        "nvme0n1": {
            "holders": [], 
            "host": "Non-Volatile memory controller: Amazon.com, Inc. Device 8061", 
            "links": {
                "ids": [
                    "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f", 
                    "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1", 
                    "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001"
                ], 
                "labels": [], 
                "masters": [], 
                "uuids": []
            }, 
            "model": "Amazon Elastic Block Store", 
            "partitions": {
                "nvme0n1p1": {
                    "holders": [], 
                    "links": {
                        "ids": [
                            "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1-part1", 
                            "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-part1", 
                            "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001-part1"
                        ], 
                        "labels": [
                            "\\x2f"
                        ], 
                        "masters": [], 
                        "uuids": [
                            "902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
                        ]
                    }, 
                    "sectors": "16773087", 
                    "sectorsize": 512, 
                    "size": "8.00 GB", 
                    "start": "4096", 
                    "uuid": "902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
                }, 
                "nvme0n1p128": {
                    "holders": [], 
                    "links": {
                        "ids": [
                            "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-ns-1-part128", 
                            "nvme-Amazon_Elastic_Block_Store_vol0775c6f05322fbc1f-part128", 
                            "nvme-nvme.1d0f-766f6c3037373563366630353332326662633166-416d617a6f6e20456c617374696320426c6f636b2053746f7265-00000001-part128"
                        ], 
                        "labels": [], 
                        "masters": [], 
                        "uuids": []
                    }, 
                    "sectors": "2048", 
                    "sectorsize": 512, 
                    "size": "1.00 MB", 
                    "start": "2048", 
                    "uuid": null
                }
            }, 
            "removable": "0", 
            "rotational": "0", 
            "sas_address": null, 
            "sas_device_handle": null, 
            "scheduler_mode": "none", 
            "sectors": "16777216", 
            "sectorsize": "512", 
            "serial": "vol0775c6f05322fbc1f", 
            "size": "8.00 GB", 
            "support_discard": "0", 
            "vendor": null, 
            "virtual": 1
        }
    }, 
    "ansible_distribution": "Amazon", 
    "ansible_distribution_file_parsed": true, 
    "ansible_distribution_file_path": "/etc/os-release", 
    "ansible_distribution_file_variety": "Amazon", 
    "ansible_distribution_major_version": "2", 
    "ansible_distribution_minor_version": "NA", 
    "ansible_distribution_release": "NA", 
    "ansible_distribution_version": "2", 
    "ansible_dns": {
        "nameservers": [
            "172.31.0.2"
        ], 
        "options": {
            "attempts": "5", 
            "timeout": "2"
        }, 
        "search": [
            "ec2.internal"
        ]
    }, 
    "ansible_domain": "ec2.internal", 
    "ansible_effective_group_id": 0, 
    "ansible_effective_user_id": 0, 
    "ansible_env": {
        "HOME": "/root", 
        "LANG": "en_US.UTF-8", 
        "LOGNAME": "root", 
        "LS_COLORS": "rs=0:di=38;5;27:ln=38;5;51:mh=44;38;5;15:pi=40;38;5;11:so=38;5;13:do=38;5;5:bd=48;5;232;38;5;11:cd=48;5;232;38;5;3:or=48;5;232;38;5;9:mi=05;48;5;232;38;5;15:su=48;5;196;38;5;15:sg=48;5;11;38;5;16:ca=48;5;196;38;5;226:tw=48;5;10;38;5;16:ow=48;5;10;38;5;21:st=48;5;21;38;5;15:ex=38;5;34:*.tar=38;5;9:*.tgz=38;5;9:*.arc=38;5;9:*.arj=38;5;9:*.taz=38;5;9:*.lha=38;5;9:*.lz4=38;5;9:*.lzh=38;5;9:*.lzma=38;5;9:*.tlz=38;5;9:*.txz=38;5;9:*.tzo=38;5;9:*.t7z=38;5;9:*.zip=38;5;9:*.z=38;5;9:*.Z=38;5;9:*.dz=38;5;9:*.gz=38;5;9:*.lrz=38;5;9:*.lz=38;5;9:*.lzo=38;5;9:*.xz=38;5;9:*.bz2=38;5;9:*.bz=38;5;9:*.tbz=38;5;9:*.tbz2=38;5;9:*.tz=38;5;9:*.deb=38;5;9:*.rpm=38;5;9:*.jar=38;5;9:*.war=38;5;9:*.ear=38;5;9:*.sar=38;5;9:*.rar=38;5;9:*.alz=38;5;9:*.ace=38;5;9:*.zoo=38;5;9:*.cpio=38;5;9:*.7z=38;5;9:*.rz=38;5;9:*.cab=38;5;9:*.jpg=38;5;13:*.jpeg=38;5;13:*.gif=38;5;13:*.bmp=38;5;13:*.pbm=38;5;13:*.pgm=38;5;13:*.ppm=38;5;13:*.tga=38;5;13:*.xbm=38;5;13:*.xpm=38;5;13:*.tif=38;5;13:*.tiff=38;5;13:*.png=38;5;13:*.svg=38;5;13:*.svgz=38;5;13:*.mng=38;5;13:*.pcx=38;5;13:*.mov=38;5;13:*.mpg=38;5;13:*.mpeg=38;5;13:*.m2v=38;5;13:*.mkv=38;5;13:*.webm=38;5;13:*.ogm=38;5;13:*.mp4=38;5;13:*.m4v=38;5;13:*.mp4v=38;5;13:*.vob=38;5;13:*.qt=38;5;13:*.nuv=38;5;13:*.wmv=38;5;13:*.asf=38;5;13:*.rm=38;5;13:*.rmvb=38;5;13:*.flc=38;5;13:*.avi=38;5;13:*.fli=38;5;13:*.flv=38;5;13:*.gl=38;5;13:*.dl=38;5;13:*.xcf=38;5;13:*.xwd=38;5;13:*.yuv=38;5;13:*.cgm=38;5;13:*.emf=38;5;13:*.axv=38;5;13:*.anx=38;5;13:*.ogv=38;5;13:*.ogx=38;5;13:*.aac=38;5;45:*.au=38;5;45:*.flac=38;5;45:*.mid=38;5;45:*.midi=38;5;45:*.mka=38;5;45:*.mp3=38;5;45:*.mpc=38;5;45:*.ogg=38;5;45:*.ra=38;5;45:*.wav=38;5;45:*.axa=38;5;45:*.oga=38;5;45:*.spx=38;5;45:*.xspf=38;5;45:", 
        "MAIL": "/var/mail/ec2-user", 
        "PATH": "/sbin:/bin:/usr/sbin:/usr/bin", 
        "PWD": "/home/ec2-user", 
        "SHELL": "/bin/bash", 
        "SHLVL": "1", 
        "SUDO_COMMAND": "/bin/sh -c echo BECOME-SUCCESS-znqjeexvodsbibygzzujoenlpwfpehyn ; /usr/bin/python /home/ec2-user/.ansible/tmp/ansible-tmp-1684418257.03-4424-21525028954014/AnsiballZ_setup.py", 
        "SUDO_GID": "1000", 
        "SUDO_UID": "1000", 
        "SUDO_USER": "ec2-user", 
        "TERM": "xterm-256color", 
        "USER": "root", 
        "USERNAME": "root", 
        "XDG_SESSION_ID": "8", 
        "_": "/usr/bin/python"
    }, 
    "ansible_eth0": {
        "active": true, 
        "device": "eth0", 
        "features": {
            "esp_hw_offload": "off [fixed]", 
            "esp_tx_csum_hw_offload": "off [fixed]", 
            "fcoe_mtu": "off [fixed]", 
            "generic_receive_offload": "on", 
            "generic_segmentation_offload": "on", 
            "highdma": "on", 
            "hw_tc_offload": "off [fixed]", 
            "l2_fwd_offload": "off [fixed]", 
            "large_receive_offload": "off [fixed]", 
            "loopback": "off [fixed]", 
            "macsec_hw_offload": "off [fixed]", 
            "netns_local": "off [fixed]", 
            "ntuple_filters": "off [fixed]", 
            "receive_hashing": "on", 
            "rx_all": "off [fixed]", 
            "rx_checksumming": "off [fixed]", 
            "rx_fcs": "off [fixed]", 
            "rx_gro_hw": "off [fixed]", 
            "rx_gro_list": "off", 
            "rx_udp_tunnel_port_offload": "off [fixed]", 
            "rx_vlan_filter": "off [fixed]", 
            "rx_vlan_offload": "off [fixed]", 
            "rx_vlan_stag_filter": "off [fixed]", 
            "rx_vlan_stag_hw_parse": "off [fixed]", 
            "scatter_gather": "on", 
            "tcp_segmentation_offload": "off", 
            "tls_hw_record": "off [fixed]", 
            "tls_hw_rx_offload": "off [fixed]", 
            "tls_hw_tx_offload": "off [fixed]", 
            "tx_checksum_fcoe_crc": "off [fixed]", 
            "tx_checksum_ip_generic": "off [fixed]", 
            "tx_checksum_ipv4": "on", 
            "tx_checksum_ipv6": "off [fixed]", 
            "tx_checksum_sctp": "off [fixed]", 
            "tx_checksumming": "on", 
            "tx_esp_segmentation": "off [fixed]", 
            "tx_fcoe_segmentation": "off [fixed]", 
            "tx_gre_csum_segmentation": "off [fixed]", 
            "tx_gre_segmentation": "off [fixed]", 
            "tx_gso_list": "off [fixed]", 
            "tx_gso_partial": "off [fixed]", 
            "tx_gso_robust": "off [fixed]", 
            "tx_ipxip4_segmentation": "off [fixed]", 
            "tx_ipxip6_segmentation": "off [fixed]", 
            "tx_lockless": "off [fixed]", 
            "tx_nocache_copy": "off", 
            "tx_scatter_gather": "on", 
            "tx_scatter_gather_fraglist": "off [fixed]", 
            "tx_sctp_segmentation": "off [fixed]", 
            "tx_tcp6_segmentation": "off [fixed]", 
            "tx_tcp_ecn_segmentation": "off [fixed]", 
            "tx_tcp_mangleid_segmentation": "off [fixed]", 
            "tx_tcp_segmentation": "off [fixed]", 
            "tx_tunnel_remcsum_segmentation": "off [fixed]", 
            "tx_udp_segmentation": "off [fixed]", 
            "tx_udp_tnl_csum_segmentation": "off [fixed]", 
            "tx_udp_tnl_segmentation": "off [fixed]", 
            "tx_vlan_offload": "off [fixed]", 
            "tx_vlan_stag_hw_insert": "off [fixed]", 
            "udp_fragmentation_offload": "off", 
            "vlan_challenged": "off [fixed]"
        }, 
        "hw_timestamp_filters": [], 
        "ipv4": {
            "address": "172.31.81.127", 
            "broadcast": "172.31.95.255", 
            "netmask": "255.255.240.0", 
            "network": "172.31.80.0"
        }, 
        "ipv6": [
            {
                "address": "fe80::1058:63ff:fed8:cfd9", 
                "prefix": "64", 
                "scope": "link"
            }
        ], 
        "macaddress": "12:58:63:d8:cf:d9", 
        "module": "ena", 
        "mtu": 9001, 
        "pciid": "0000:00:05.0", 
        "promisc": false, 
        "timestamping": [
            "tx_software", 
            "rx_software", 
            "software"
        ], 
        "type": "ether"
    }, 
    "ansible_fibre_channel_wwn": [], 
    "ansible_fips": false, 
    "ansible_form_factor": "Other", 
    "ansible_fqdn": "ip-172-31-81-127.ec2.internal", 
    "ansible_hostname": "ip-172-31-81-127", 
    "ansible_hostnqn": "", 
    "ansible_interfaces": [
        "lo", 
        "eth0"
    ], 
    "ansible_is_chroot": false, 
    "ansible_iscsi_iqn": "", 
    "ansible_kernel": "5.10.178-162.673.amzn2.x86_64", 
    "ansible_kernel_version": "#1 SMP Mon Apr 24 23:34:06 UTC 2023", 
    "ansible_lo": {
        "active": true, 
        "device": "lo", 
        "features": {
            "esp_hw_offload": "off [fixed]", 
            "esp_tx_csum_hw_offload": "off [fixed]", 
            "fcoe_mtu": "off [fixed]", 
            "generic_receive_offload": "on", 
            "generic_segmentation_offload": "on", 
            "highdma": "on [fixed]", 
            "hw_tc_offload": "off [fixed]", 
            "l2_fwd_offload": "off [fixed]", 
            "large_receive_offload": "off [fixed]", 
            "loopback": "on [fixed]", 
            "macsec_hw_offload": "off [fixed]", 
            "netns_local": "on [fixed]", 
            "ntuple_filters": "off [fixed]", 
            "receive_hashing": "off [fixed]", 
            "rx_all": "off [fixed]", 
            "rx_checksumming": "on [fixed]", 
            "rx_fcs": "off [fixed]", 
            "rx_gro_hw": "off [fixed]", 
            "rx_gro_list": "off", 
            "rx_udp_tunnel_port_offload": "off [fixed]", 
            "rx_vlan_filter": "off [fixed]", 
            "rx_vlan_offload": "off [fixed]", 
            "rx_vlan_stag_filter": "off [fixed]", 
            "rx_vlan_stag_hw_parse": "off [fixed]", 
            "scatter_gather": "on", 
            "tcp_segmentation_offload": "on", 
            "tls_hw_record": "off [fixed]", 
            "tls_hw_rx_offload": "off [fixed]", 
            "tls_hw_tx_offload": "off [fixed]", 
            "tx_checksum_fcoe_crc": "off [fixed]", 
            "tx_checksum_ip_generic": "on [fixed]", 
            "tx_checksum_ipv4": "off [fixed]", 
            "tx_checksum_ipv6": "off [fixed]", 
            "tx_checksum_sctp": "on [fixed]", 
            "tx_checksumming": "on", 
            "tx_esp_segmentation": "off [fixed]", 
            "tx_fcoe_segmentation": "off [fixed]", 
            "tx_gre_csum_segmentation": "off [fixed]", 
            "tx_gre_segmentation": "off [fixed]", 
            "tx_gso_list": "off [fixed]", 
            "tx_gso_partial": "off [fixed]", 
            "tx_gso_robust": "off [fixed]", 
            "tx_ipxip4_segmentation": "off [fixed]", 
            "tx_ipxip6_segmentation": "off [fixed]", 
            "tx_lockless": "on [fixed]", 
            "tx_nocache_copy": "off [fixed]", 
            "tx_scatter_gather": "on [fixed]", 
            "tx_scatter_gather_fraglist": "on [fixed]", 
            "tx_sctp_segmentation": "on", 
            "tx_tcp6_segmentation": "on", 
            "tx_tcp_ecn_segmentation": "on", 
            "tx_tcp_mangleid_segmentation": "on", 
            "tx_tcp_segmentation": "on", 
            "tx_tunnel_remcsum_segmentation": "off [fixed]", 
            "tx_udp_segmentation": "off [fixed]", 
            "tx_udp_tnl_csum_segmentation": "off [fixed]", 
            "tx_udp_tnl_segmentation": "off [fixed]", 
            "tx_vlan_offload": "off [fixed]", 
            "tx_vlan_stag_hw_insert": "off [fixed]", 
            "udp_fragmentation_offload": "off", 
            "vlan_challenged": "on [fixed]"
        }, 
        "hw_timestamp_filters": [], 
        "ipv4": {
            "address": "127.0.0.1", 
            "broadcast": "", 
            "netmask": "255.0.0.0", 
            "network": "127.0.0.0"
        }, 
        "ipv6": [
            {
                "address": "::1", 
                "prefix": "128", 
                "scope": "host"
            }
        ], 
        "mtu": 65536, 
        "promisc": false, 
        "timestamping": [
            "tx_software", 
            "rx_software", 
            "software"
        ], 
        "type": "loopback"
    }, 
    "ansible_local": {}, 
    "ansible_lsb": {}, 
    "ansible_lvm": {
        "lvs": {}, 
        "pvs": {}, 
        "vgs": {}
    }, 
    "ansible_machine": "x86_64", 
    "ansible_machine_id": "ec203fddcdfd90321c633e538830144c", 
    "ansible_memfree_mb": 71, 
    "ansible_memory_mb": {
        "nocache": {
            "free": 340, 
            "used": 587
        }, 
        "real": {
            "free": 71, 
            "total": 927, 
            "used": 856
        }, 
        "swap": {
            "cached": 0, 
            "free": 0, 
            "total": 0, 
            "used": 0
        }
    }, 
    "ansible_memtotal_mb": 927, 
    "ansible_mounts": [
        {
            "block_available": 1395998, 
            "block_size": 4096, 
            "block_total": 2094075, 
            "block_used": 698077, 
            "device": "/dev/nvme0n1p1", 
            "fstype": "xfs", 
            "inode_available": 4066976, 
            "inode_total": 4193216, 
            "inode_used": 126240, 
            "mount": "/", 
            "options": "rw,noatime,attr2,inode64,logbufs=8,logbsize=32k,noquota", 
            "size_available": 5718007808, 
            "size_total": 8577331200, 
            "uuid": "902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
        }
    ], 
    "ansible_nodename": "ip-172-31-81-127.ec2.internal", 
    "ansible_os_family": "RedHat", 
    "ansible_pkg_mgr": "yum", 
    "ansible_proc_cmdline": {
        "BOOT_IMAGE": "/boot/vmlinuz-5.10.178-162.673.amzn2.x86_64", 
        "biosdevname": "0", 
        "console": [
            "tty0", 
            "ttyS0,115200n8"
        ], 
        "net.ifnames": "0", 
        "nvme_core.io_timeout": "4294967295", 
        "rd.emergency": "poweroff", 
        "rd.shell": "0", 
        "ro": true, 
        "root": "UUID=902c5313-0003-4b1a-a5ef-6981dc3fd4a7"
    }, 
    "ansible_processor": [
        "0", 
        "GenuineIntel", 
        "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", 
        "1", 
        "GenuineIntel", 
        "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"
    ], 
    "ansible_processor_cores": 1, 
    "ansible_processor_count": 1, 
    "ansible_processor_nproc": 2, 
    "ansible_processor_threads_per_core": 2, 
    "ansible_processor_vcpus": 2, 
    "ansible_product_name": "t3.micro", 
    "ansible_product_serial": "ec2ac185-7093-d637-1f5a-9da9458cc823", 
    "ansible_product_uuid": "ec2ac185-7093-d637-1f5a-9da9458cc823", 
    "ansible_product_version": "NA", 
    "ansible_python": {
        "executable": "/usr/bin/python", 
        "has_sslcontext": true, 
        "type": "CPython", 
        "version": {
            "major": 2, 
            "micro": 18, 
            "minor": 7, 
            "releaselevel": "final", 
            "serial": 0
        }, 
        "version_info": [
            2, 
            7, 
            18, 
            "final", 
            0
        ]
    }, 
    "ansible_python_version": "2.7.18", 
    "ansible_real_group_id": 0, 
    "ansible_real_user_id": 0, 
    "ansible_selinux": {
        "status": "disabled"
    }, 
    "ansible_selinux_python_present": true, 
    "ansible_service_mgr": "systemd", 
    "ansible_ssh_host_key_ecdsa_public": "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAZdCW8E1h4a4+K0e+cGQx7TfcPp7o0r+SROJjubwm736ZNLu0adIwAUt+j7MxdWHTpnAknnqGXAurx5rbIPbwA=", 
    "ansible_ssh_host_key_ecdsa_public_keytype": "ecdsa-sha2-nistp256", 
    "ansible_ssh_host_key_ed25519_public": "AAAAC3NzaC1lZDI1NTE5AAAAIHFuQJcr3CbAiF6xqDKwDQ9B4anVEJk/b5+blBatN5m7", 
    "ansible_ssh_host_key_ed25519_public_keytype": "ssh-ed25519", 
    "ansible_ssh_host_key_rsa_public": "AAAAB3NzaC1yc2EAAAADAQABAAABAQDgXZt/1iwGoe7gPJsiXD49wfTnqPMtPPhdNB7rUl7S+WTz2Z09p+BGlCBg0y57OGZg0m1Kzx5YCUD1u4G474vAws/NJy663yjH0xUB0nW+KCsJJZ232P35zVz+J/gyaQ9gDuj2nLsPUXXtMsHEQnag4xB8iTq75QjjYOnLGRxt6p7sxkb9C4ruRIyZGm6SyDjwNnwAoTdy5WWojc1XPZUYUjiiBJKycIAselr5zqnxqeXk/6KwqpIzR6JzcXf+d1ma4lgo2otiptBgEZ5h5xPHixVKbs49t6DtXp7zKl5TlzYLVsn+I0iBLJowdCZ3SQfH5qtMLvBQ2Jh2Nl24NxJJ", 
    "ansible_ssh_host_key_rsa_public_keytype": "ssh-rsa", 
    "ansible_swapfree_mb": 0, 
    "ansible_swaptotal_mb": 0, 
    "ansible_system": "Linux", 
    "ansible_system_capabilities": [], 
    "ansible_system_capabilities_enforced": "False", 
    "ansible_system_vendor": "Amazon EC2", 
    "ansible_uptime_seconds": 2997, 
    "ansible_user_dir": "/root", 
    "ansible_user_gecos": "root", 
    "ansible_user_gid": 0, 
    "ansible_user_id": "root", 
    "ansible_user_shell": "/bin/bash", 
    "ansible_user_uid": 0, 
    "ansible_userspace_architecture": "x86_64", 
    "ansible_userspace_bits": "64", 
    "ansible_virtualization_role": "guest", 
    "ansible_virtualization_tech_guest": [
        "kvm"
    ], 
    "ansible_virtualization_tech_host": [], 
    "ansible_virtualization_type": "kvm", 
    "discovered_interpreter_python": "/usr/bin/python", 
    "gather_subset": [
        "all"
    ], 
    "module_setup": true
}