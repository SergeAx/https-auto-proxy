WTF?
====

https proxy with authorization and auto Letsenrypt

How to use
----------

Need real resolvable and accessible at port 80 host with symbolic name.

```
touch /opt/https-auto-proxy/certs

docker run --name https-auto-proxy -d \
    -p 80:80 \
    -p 443:443 \
    -e "PROXY_AUTH=user:password,user2:password2,user3,user4" \
    -e "HOST=fuckrkn.example.com" \
    -e "ADMIN_EMAIL=admin@example.com" \
    -v /opt/https-auto-proxy/certs:/app:rw \
    sergeax/https-auto-proxy
```

Derived from and/or inspired by
-------------------------------

https://medium.com/@mlowicki/http-s-proxy-in-golang-in-less-than-100-lines-of-code-6a51c2f2c38c

https://blog.kowalczyk.info/article/Jl3G/https-for-free-in-go-with-little-help-of-lets-encrypt.html

https://github.com/aspcartman/mysocks