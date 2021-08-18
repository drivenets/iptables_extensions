# novrf
A custom match, for matching interfaces in the default/non-default VRF.

Part of SW-60508.

# Usage
1. `-m novrf --input`    - Match ingress/forwarded packets, whose input device is in the default VRF.
2. `-m novrf --output`   - Match egress/forwarded packets, whose output device is in the default VRF.
3. `-m novrf ! --input`  - Match ingress/forwarded packets, whose input device is in *some* non-default VRF.
4. `-m novrf ! --output` - match egress/forwarded packets, whose output device is in *some* non-default VRF

# Common errors
The kmodule detects installing a match on a wrong chain (installing an `[!] --input`/`[!] --output` match in a chain that only has an output/input device).

The list of chain, with the valid interfaces, are:
* PREROUTING, INPUT   -> Only `[!] --input` is valid.
* FORWARD             -> Both `[!] --input` and `[!] --output` are valid.
* OUTPUT, POSTROUTING -> Only `[!] --output` is valid.

For example, using an output device in PREROUTING (an input-only chain) will fail with:

```
# iptables -t nat -A PREROUTING -m novrf --output -j LOG
iptables: Invalid argument. Run `dmesg' for more information.
# dmesg
[27016.194467] xt_novrf: Rule used from hooks PREROUTING, but output device is valid only from FORWARD/OUTPUT/POSTROUTING
```

# Example
To perform SNAT to 2.2.2.2 for all UDP packets with dport 53 which are sent over the default VRF:
```
iptables -t nat -A POSTROUTING -p udp -m udp --dport 53 -m novrf --output -j SNAT --to-source 2.2.2.2
```
