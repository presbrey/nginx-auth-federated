# nginx-auth-federated

This service provides federated authentication for nginx via the [http_auth_request API](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

## Installation

`go get -u github.com/presbrey/nginx-auth-federated`

Use a process manager like systemd or [supervisord](supervisord.org) to keep `nginx-auth-federated` running.

## Features

* authentication cache w/ configurable TTL
* bind DN template integrates with any LDAP provider/schema
* supports OneLogin Federated Authentication