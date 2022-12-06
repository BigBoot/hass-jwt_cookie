# Set Up SSO using Caddy and jwt_cookie

Note: In the following guide `my.home.assistant` will be used for demonstrative purposes, replace this with your own domain.

What you will end up after following this guide
- HomeAssistant reachable on `my.home.assistant` with automatic HTTPS certificates managed by Caddy
- Internal services reachable on `svc1.my.home.assistant` etc.
- Seamless SSO for HomeAssistant and services

## Assumptions & Requirements
This guide assumes the following:
- You do have access to manage the DNS entries for `my.home.assistant` (i.e. you own the domain)
- You are using HassOS or Supervised (to install the caddy addon)
- You already set up your DNS so `my.home.assistants` points to your HomeAssitant instance
- You already set up your DNS so `*.my.home.assistants` points to your HomeAssitant instance
- Your HomeAssistant is publicly reachable on Port 80 & 443
- You already have HACS running

Note that none of those are hard requirements but for the sake of simplicity this is the only setup we will be looking at.

## 1. Install jwt_cookie:
- Add the jwt_cookie HACS repository: [![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=bigboot&repository=hass-jwt_cookie&category=integration)
- Install the jwt_cookie intergration in HACS

## 2. Install Caddy2
- Add the Caddy2 addon repository:
 [![Add Caddy2 addon repository](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Feinschmidt%2Fhassio-addons)
- Install the Caddy2 addon: [![Install the Caddy2 addon](https://my.home-assistant.io/badges/supervisor_store.svg)](https://my.home-assistant.io/redirect/supervisor_store/)
- Enable AutoStart & Watchdog  for the Caddy2 addon
- Configure the Caddy2 addon:
  set `config_path` to `/config/Caddyfile`
  set `custom_binary_path` to `/config/caddy`
- [Download Caddy with the caddy-security plugin](https://caddyserver.com/download?package=github.com%2Fgreenpau%2Fcaddy-security) and save it as `/config/caddy`


## 3. Configure Caddy, and HomeAssistant
- Create the file `/config/Caddyfile` with the following content:
```Caddyfile
{
	security {
        # Set up a policy called homeassistant
		authorization policy homeassistant {
			set token sources cookie
			crypto key verify from file /config/jwt_cookie.pem
			set auth url https://my.home.assistant/auth/jwt_cookie
			crypto key token name jwt_access_token
			allow roles user
		}
	}
}

# reverse proxy to home assistant without authentication
my.home.assistant {
	reverse_proxy localhost:8123
}

# reverse proxy svc1 with enabled authentication
svc1.my.home.assistant {
	route {
		authorize with homeassistant
		reverse_proxy <your_local_service_ip/domain:port>
	}
}
```
- Create or edit your `/config/configuration.yaml`:
```yaml
http:
  use_x_forwarded_for: true
  trusted_proxies:
    - 127.0.0.1
    - ::1
  cors_allowed_origins:
    - https://my.home.assistant

jwt_cookie:
  domain: ".my.home.assistant"
  private_key_file: /config/jwt_cookie.key
```

## 4. Restart HomeAssistant
That's it, everything should be working now, if something is not working as expected check your HomeAssistant and Caddy2 logs.

