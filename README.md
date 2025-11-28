# honeypot-middleware

Traefik middleware for observing vulnerability crawler behavior. It also directs these bots away from the real target.

# usage

In your traefik config:
```
experimental:
  plugins:
    honeypot-middleware:
      moduleName: github.com/CorySanin/honeypot-middleware
      version: v0.0.1
```

in your providers definition file:
```
http:  
  middlewares:
    honeypot:
      plugin:
        honeypot-middleware:
          verbose: true
```

The honeypot can technically be configured further, but I don't recommend it.

Last, add `honeypot@file` to your target's middlewares.

# development

In order to embed the response bodies, there's a ejs template that is used to generate the final plugin. Edit [preprocessor/plugin-template.go](preprocessor/plugin-template.go). Make the plugin with `make`. Requires nodejs and npm. The `docker-compose.yml` definition is ready to test the plugin.
