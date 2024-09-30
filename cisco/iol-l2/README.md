# Cisco IOL-L2 (IOS on Linux)

This is the containerlab/vrnetlab image Cisco IOL.

CML recently introduced IOL-XE which compared to other Cisco images, runs very lightly since it executes purely as a binary and has no requirement for a virtualisation layer.

There are two types of IOL you can obtain:

- IOL, meant for Layer 3 operation as a router.
- IOL-L2, meant to act as a L2/L2+ switch.

## Building the image

> This README is for the IOL-L2 image, if you are trying to build the regular IOL/L3 image, go to the `../iol` directory.

Copy the `x86_64_crb_linux-adventerprisek9-ms` and rename it to `cisco_iol-x.y.z.bin` (x.y.z being the version number). For example `cisco_iol-17.12.01.bin`. The `.bin` extension is important.

> If you are getting the image from the CML refplat, the L2 image is under the `ioll2-xe-x.y.z` directory.

Execute 
```
make docker-image
```

and the image will be built and tagged. You can view the image by executing `docker images`.

## Usage

You can define the image easily and use it in a topolgy.

```yaml
# topology.clab.yaml
name: mylab
topology:
  nodes:
    iol:
      kind: cisco_iol
      image: vrnetlab/vr-iol-l2:<tag>
```
