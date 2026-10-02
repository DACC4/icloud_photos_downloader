# iCloud Authentication

## Multi-Factor Authentication

If your Apple account has two-factor authentication (multi-factor authentication, MFA) enabled,
you will be prompted for a code when you run the script. Two-factor authentication will expire after an interval set by Apple,
at which point you will have to re-authenticate. This interval is currently two months. Apple requires MFA for all new accounts.

You can receive an email notification when two-factor authentication expires by passing the
`--smtp-username` and `--smtp-password` options. Emails will be sent to `--smtp-username` by default,
or you can send to a different email address with `--notification-email`.

If you want to send notification emails using your Gmail account, and you have enabled two-factor authentication, you will need to generate an App Password at <https://myaccount.google.com/apppasswords>.

## MFA Providers

```{versionadded} 1.21.0
```

There are two ways to provide an MFA code to `icloudpd`:
- Using console
- Using web interface

The choice can be made with [`--mfa-provider`](mfa-provider-parameter) parameter.

Default: *console*
Other options: *webui*

## Access from Mainland China

Access to iCloud.com is blocked from mainland China. `icloudpd` can be used with the [`--domain cn`](domain-parameter) parameter to support downloading iCloud Photos from mainland China; however, people have reported mixed results with that parameter.

(security-keys)=
## Security Keys (FIDO2)

```{versionadded} Unreleased
```

If your Apple account is protected with [Security Keys](https://support.apple.com/en-us/102637), Apple does not send codes to trusted devices
or phone numbers for web sign-in. Instead, `icloudpd` asks you to touch one of your FIDO2 security keys (e.g. a YubiKey) while it authenticates.

The security key must be connected (USB) to the machine running `icloudpd`. This also applies when the [`webui`](mfa-provider-parameter) MFA provider is used:
the web interface cannot relay the key from your browser, because the key response is bound to Apple's sign-in site.

On Linux, the user running `icloudpd` needs read/write access to the `/dev/hidraw*` device of the key. Most distributions grant it to the logged-in
user through udev rules (often shipped with packages like `libfido2` or `yubikey-manager`).

### Headless servers and Docker

If `icloudpd` runs on a server, NAS or in Docker, where the key cannot be plugged in, authenticate on a computer that has the key and copy the session
to the server:

1. On the computer with the key, run:
   ```
   icloudpd --username my@email.address --cookie-directory ./cookies --auth-only
   ```
2. Copy both files created for your account in `./cookies` (the cookie jar named after the username and the `.session` file) into the
   [cookie directory](cookie-directory-parameter) used by `icloudpd` on the server. With Docker, mount a host folder into the container
   (e.g. `-v /path/to/cookies:/cookies`) and pass `--cookie-directory /cookies` so the session survives container restarts.
3. Run `icloudpd` on the server as usual. It reuses the session without asking for MFA.

When the session expires (see above), `icloudpd` on the server fails with a security key error, and sends an email notification if SMTP is configured.
Repeat the steps above to renew it.

Alternatively, pass the key into the container with `--device /dev/hidraw0` (the device number may differ) and keep it plugged into the server.

## ADP

Advanced Data Protection (ADP) for iCloud accounts is not supported because `icloudpd` simulates web access, which is disabled with ADP.

## Occasional Errors

Some authentication errors may be resolved by clearing the `.pyicloud` subfolder in the user's home directory. [Example](https://github.com/icloud-photos-downloader/icloud_photos_downloader/issues/772#issuecomment-1950963522)

(password-providers)=
## Password Providers

```{versionadded} 1.20.0
```
```{versionadded} 1.21.0
WebUI support
```

Passwords for iCloud access can be supplied by the user in four ways:
- Using [`--password`](password-parameter) command line parameter
- Using keyring
- Using console
- Using web interface

It is possible to specify which of these four ways `icloudpd` should use, by specifying them with the [`--password-provider`](password-provider-parameter) parameter. More than one can be specified and the order
of providers matches the order they will be checked for a password. E.g., `--password-provider keyring --password-provider console` means that `icloudpd` will check the password in the keyring first and then, if no password is found, ask for a password in the console.

The keyring password provider, if specified, saves the valid password back into the keyring.

Console and Web UI are not compatible with each other. Console or WebUI providers, if specified, must be last in the list of providers because they cannot be skipped.

Default set and order of providers are: *parameter*, *keyring*, *console*

### Managing System Keyring

You can store your password in the system keyring or delete it from there using the `icloud` command-line tool:

```
$ icloud --username jappleseed@apple.com
ICloud Password for jappleseed@apple.com:
Save password in keyring? (y/N)
```

If you would like to delete a password stored in your system keyring,
you can clear a stored password using the `--delete-from-keyring` command-line option:

``` sh
icloud --username jappleseed@apple.com --delete-from-keyring
```

```{note}
Use `icloud`, not `icloudpd`
```

(multiple-accounts-and-configs)=
## Using Multiple Accounts and Config

`icloudpd` can process iCloud collections for multiple accounts or use multiple configs for one account. This is achieved by specifying the `--username` parameter multiple times: any options specified after `--username` will be applied to the mentioned user only. Parameters specified before the first `--username` work as defaults for all other user configs. Global app-wide settings can be specified anywhere.

### Example: using two user accounts

```
$ icloudpd --use-os-locale --cookie-directory ./cookies --username alice@apple.com --directory ./alice --username bob@apple.com --directory ./bob
```

Explanation

- `--use-os-locale` is a global parameter and can be used anywhere
- `--cookie-directory` is a default for both users; it is okay to use the same folder since sessions and cookies are stored in files based on the user name, so they would not collide
- `--directory ./alice` specifies that all photos for Alice will be downloaded into the ./alice folder
- `--directory ./bob` specifies that all photos for Bob will be downloaded into the ./bob folder

### Example: using two configs for one account

```
$ icloudpd --cookie-directory ./cookies --username alice@apple.com --directory ./photos --skip-videos --username alice@apple.com --directory ./videos --skip-photos --use-os-locale
```

Explanation

- `--cookie-directory` is a default for both configs
- `--directory ./photos --skip-videos` specifies that all photos for Alice will be downloaded into the ./photos folder
- `--directory ./videos --skip-photos` specifies that all videos for Alice will be downloaded into the ./videos folder
- `--use-os-locale` is a global parameter and can be used anywhere

```{versionadded} 1.32.0
```
