# lazy-nagios-freeipa

This is a lazy freeipa plugin for nagios. The idea is to provide very basic
checks against the API and also LDAP where necessary.

Inspiration comes from various wrappers, scripts, and modules online provided
by [FreeIPA](https://freeipa.org) itself.

## Example Calls

```
python3 lazy_freeipa_webauth.py --host ipa01.example.com --username label --password "somePassword1"
```
