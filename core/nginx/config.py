#!/usr/bin/python3

import os
import logging as log
import sys
from socrate import system, conf

args = os.environ.copy()

log.basicConfig(stream=sys.stderr, level=args.get("LOG_LEVEL", "WARNING"))

# Get the first DNS server
with open("/etc/resolv.conf") as handle:
    content = handle.read().split()
    args["RESOLVER"] = content[content.index("nameserver") + 1]

args["ADMIN_ADDRESS"] = system.get_host_address_from_environment("ADMIN", "admin")
args["ANTISPAM_WEBUI_ADDRESS"] = system.get_host_address_from_environment("ANTISPAM_WEBUI", "antispam:11334")
if args["WEBMAIL"] != "none":
    args["WEBMAIL_ADDRESS"] = system.get_host_address_from_environment("WEBMAIL", "webmail")
if args["WEBDAV"] != "none":
    args["WEBDAV_ADDRESS"] = system.get_host_address_from_environment("WEBDAV", "webdav:5232")

# TLS configuration
cert_name = os.getenv("TLS_CERT_FILENAME", default="cert.pem")
keypair_name = os.getenv("TLS_KEYPAIR_FILENAME", default="key.pem")
cert_name_https = os.getenv("TLS_CERT_FILENAME_HTTPS", default="cert-http.pem")
keypair_name_https = os.getenv("TLS_KEYPAIR_FILENAME_HTTPS", default="key-http.pem")
args["TLS"] = {
    "cert": ("/certs/%s" % cert_name, "/certs/%s" % keypair_name, "/certs/%s" % cert_name, "/certs/%s" % keypair_name),
    "cert-https-cert": ("/certs/%s" % cert_name, "/certs/%s" % keypair_name, "/certs/%s" % cert_name_https, "/certs/%s" % keypair_name_https),
    "letsencrypt": ("/certs/letsencrypt/live/mailu/fullchain.pem",
        "/certs/letsencrypt/live/mailu/privkey.pem", "/certs/letsencrypt/live/mailu/fullchain.pem", "/certs/letsencrypt/live/mailu/privkey.pem"),
    "mail": ("/certs/%s" % cert_name, "/certs/%s" % keypair_name, None, None),
    "mail-letsencrypt": ("/certs/letsencrypt/live/mailu/fullchain.pem",
        "/certs/letsencrypt/live/mailu/privkey.pem", None, None),
    "mail-letsencrypt-https-cert":("/certs/letsencrypt/live/mailu/fullchain.pem", "/certs/letsencrypt/live/mailu/privkey.pem", "/certs/%s" % cert_name_https, "/certs/%s" % keypair_name_https),
    "notls": (None, None, None, None)
}[args["TLS_FLAVOR"]]

for index, file_path in enumerate(args["TLS"]):
    if file_path != None and not(os.path.exists(file_path)):
        if index < 2 and args.get("TLS_ERROR", '') != 'yes':
            print("Missing cert or key file, disabling TLS for mail")
            args["TLS_ERROR"] = "yes"
        elif index > 1 and args.get("TLS_ERROR_HTTPS",'') != 'yes':
            print("Missing cert or key file, disabling TLS for https")
            args["TLS_ERROR_HTTPS"] = "yes"

# Build final configuration paths
conf.jinja("/conf/tls.conf", args, "/etc/nginx/tls.conf")
conf.jinja("/conf/proxy.conf", args, "/etc/nginx/proxy.conf")
conf.jinja("/conf/nginx.conf", args, "/etc/nginx/nginx.conf")
if os.path.exists("/var/run/nginx.pid"):
    os.system("nginx -s reload")
