# ArpSpoofer
Man-In-The-Middle Attack

## Version Log:
v1.1 (current) - stable, not complete

## Usage
To use this MITM-attack program, you need to provide two arguments via flags:
1.  The IP address of the target you want to change, specified using the `-t` or `--target` flag.
2.  The IP address of the local gateway (router) you want to set, specified using the `-g` or `--gateway` flag.<br/>
Note: you can get the gateway IP using: `route -n`
3. You can stop the attack using `CTRL+C`.

To attack the target address, run the following command:<br/>
`sudo python3 apr_spoofer.py -t <TARGET> -g <GATEWAY>` 

Replace `<TARGET>` with the IP address of the target you want to attack and `<GATEWAY>` with gateway address.
