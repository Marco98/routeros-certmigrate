# RouterOS-Certmigrate

A tool to quickly export and import certificates in Mikrotik's RouterOS from and to a file or router

## Usage

```
Usage:
  ros-crtmigrate SOURCEADDR DSTADDR [flags]

Flags:
  -h, --help      help for ros-crtmigrate
  -r, --read      read from file instead of a remote router
  -v, --verbose   print more info when running
  -w, --write     write to file instead of a remote router
```

### Examples

```shell
ros-crtmigrate 192.168.88.10 192.168.88.20 # migrate certificates directly to another router
ros-crtmigrate 192.168.88.10 certificates.bin -w # export certificates to a local binary file
ros-crtmigrate certificates.bin 192.168.88.20 -r # import certificates from a local binary file
```
