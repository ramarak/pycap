# pycap
pycap allows you to read pcap files using python tkinter.

Filters:
- no = packet number
- src = source IP
- dst = destination IP
- src_loc = source location
- dst_loc = destination location
- proto = protocol

Filters can be combined together using a "," to separate them. Example, src_loc=[Dallas],proto=TCP

Double-clicking on a packet will display more information about it, such as, TTL, port etc...

# requirements
You will need to download the GeoLite2 City database and geoip2 library.

GeoLite2 database: https://dev.maxmind.com/geoip/geoip2/geolite2/

geoip2: pip install geoip2
