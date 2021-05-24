tfa-rs
===

tfa-rs is simple Rusty Command-Line Two-Factor Authentication Utility.

## Notes

- 2FA information is strongly encrypted, but if the master key is leaked, nothing can still be done.
- Since there is a reset command, anyone can freely reset the list.
- Do not trust this tool entirely. It is just an auxiliary tool. **Be sure to register the service on other 2FA app on your smartphone, etc**.

## Feature

- Set any master key and encrypt the service name and secret key.
- To get the OTPP code, just enter the service name. There are only 5 subcommands, and There are few command options.
  <details>
    <summary>command list (click to expand/collapse)</summary>

    - `"service_name"` :</br>try to get OTP code
      - `--clip` :</br>copy OTP code to clipboard

      - `-c, --config "config_path"` :</br>Use a custom config file

      - `--hotp "counter_value"` :</br>Generate HOTP with arguments as counters

      - `-l, --length "code_length"` :</br>Set the length of OTP code

    - `add "service_name" "service_secret_key"` :</br>add new servicekey-value to the list

    - `rm "service_name"` :</br>remove service key-value from the list

    - `list` :</br>Show the all service name from list
      - `-s, --show` :</br>Show the OTP code of service name

    - `master "your_master_key"` :</br>set the master key. if exists any key-value and not set master key yet, tfa-rs will encrypt all key-value

    - `reset` :</br>delete all key-value from the list

  </details>

## Encryption

In `tfa-rs`, the Master key is hashed using `argon2` and the service key-value is encrypted using `chacha20poly1305`.

## Install

`cargo install --git https://github.com/2vg/tfa-rs`

## Usage

See the command list in the [Feature](#Feature) section.</br>
By default, the config file is created under `XDG_CONFIG_HOME`(if none, `$HOME/.config`, even not Linux) with the filename `.tfa`.</br>
See more information: [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/)</br>

```
# optional
# The password can be up to 32 characters.
# After the 32nd character, it is automatically truncated.
tfa master "MY_STRONG_PASSWORD"

tfa add "GitHub" "GITHUBSECRETKEY"
Enter the master key: ...

# To get OTP code, just type service name
tfa "GitHub"
Enter the master key: ...
<code>

tfa rm "GitHub"
```

## Todo

- [ ] something?
