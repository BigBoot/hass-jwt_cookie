# hass-jwt_cookie

[![GitHub Release][releases-shield]][releases]
[![License][license-shield]](LICENSE)
[![hacs][hacsbadge]][hacs]
![Project Maintenance][maintenance-shield]

Create JWT Cookies every time you log in to your HomeAssistant instance.

![jwt][jwtimg]

## Why?

I wanted to reverse proxy a few of my internally reachable services and make them available through my publicly accessible HomeAssistant installation.
After looking at the available solutions I was not satisfied with any of them, here's some of the solutions I evaluated and why I disliked them.

- BasicAuth using user:password in the url
   ❌ Doesn't work in the Android/iOS App
   ❌ Makes the login details available in cleartext in the url

- Authelia
   ❌ User Management Separate from HomeAssistant
   ❌ No SSO
   ❌ Doesn't work in the Android/iOS App?

- LDAP+Authelia+HomeAssistant LDAP+Some LDAP GUI
   ❌ Very Complex
   ❌ No True SSO (You'll have to log in to Home Assistant **AND** Authelia separately)
   ❌ Doesn't work in the Android/iOS App?

- Various other similar combination of solutions like Authentik/Keycloak/... all suffer from the same fundamental problems as Authelia

So I decided to create this intergration and combine it with a reverse proxy supporting jwt auth. This ticks all of my requirements:
- ✅ Works everywhere (including the iOS/Android apps)
- ✅ True SSO
- ✅ Users are managed in HomeAssistant
- ✅ No cleartext login/passwords
- ✅ Is easily extensible to new services
- ✅ Reasonably safe

**NOTE:** By itself this integration only provides the creation of a json cookie, the actual authentication will still need to be configured in the reverse proxy, see [integrations](#integrations) for more details.

## Installation

### HACS (Recommended)

Installation is via the [Home Assistant Community Store
(HACS)](https://hacs.xyz/), which is the best place to get third-party
integrations for Home Assistant. Once you have HACS set up, simply click the button below or
follow the [instructions for adding a custom
repository](https://hacs.xyz/docs/faq/custom_repositories) and then
the integration will be available to install like any other.

[![Open your Home Assistant instance and open a repository inside the Home Assistant Community Store.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=bigboot&repository=hass-jwt_cookie&category=integration)

### Manual

1. Using the tool of choice open the directory (folder) for your HA configuration (where you find `configuration.yaml`).
2. If you do not have a `custom_components` directory (folder) there, you need to create it.
3. In the `custom_components` directory (folder) create a new folder called `jwt_cookie`.
4. Download _all_ the files from the `custom_components/jwt_cookie/` directory (folder) in this repository.
5. Place the files you downloaded in the new directory (folder) you created.
6. Restart Home Assistant

Using your HA configuration directory (folder) as a starting point you should now also have this:

```text
custom_components/jwt_cookie/__init__.py
custom_components/jwt_cookie/manifest.json
```

## Configuration

To use this component in your installation, add the following to your configuration.yaml file:

### Example configuration.yaml entry (uncomment and change if needed)

```yaml
jwt_cookie:
    # cookie_name: <cookie name> # defaults to jwt_access_token
    # audience: <jwt aud claim> # defaults to homeassistant
    # issuer: <jwt issuer> # defaults to homeassistant
    # http_only: <true/false> # defaults to true
    # secure: <true/false> # defaults to false
    # domain: <cookie domain> # defaults to the current domain, to include subdomains
                              # set this to the domain name with a leading `.`
                              # i.e. .my.hass.domain
    # public_key_file: <location to public key> # defaults to /config/jwt_cookie.pem
    # private_key_file: <location to private key> # defaults to null
                                                  # if not set no private key will be stored
                                                  # this means a new private/public key pair
                                                  # will be generated every time ha restarts
```

## Integrations

- [Caddy](/integrations/caddy.md)
- Traefik (Open for contributions, probably requires commercial edition)
- Nginx (Open for contributions, probably requires commercial edition)
- HAProxy (Open for contributions)

## Contributions are welcome!

If you want to contribute to this please read the [Contribution guidelines](CONTRIBUTING.md)

***

[hacs]: https://github.com/custom-components/hacs
[hacsbadge]: https://img.shields.io/badge/HACS-Custom-orange.svg?style=for-the-badge
[jwtimg]: jwt.png
[license-shield]: https://img.shields.io/github/license/bigboot/hass-jwt_cookie.svg?style=for-the-badge
[maintenance-shield]: https://img.shields.io/badge/maintainer-%40BigBoot-blue.svg?style=for-the-badge
[releases-shield]: https://img.shields.io/github/release/bigboot/hass-jwt_cookie.svg?style=for-the-badge
[releases]: https://github.com/bigboot/hass-jwt_cookie/releases
