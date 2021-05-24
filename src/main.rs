use anyhow::*;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Version,
};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use clap::clap_app;
use clipboard::{ClipboardContext, ClipboardProvider};
use dirs::home_dir;
use libreauth::oath::{HOTPBuilder, TOTPBuilder};
use rand_core::OsRng;
use ron::{
    de::from_reader,
    ser::{to_string_pretty, PrettyConfig},
};
use rpassword::prompt_password_stdout;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write, path::{Path, PathBuf}};

const GLOBAL_KEY: &[u8; 32] = &[
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
];

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Config {
    pub master: String,
    pub key_map: HashMap<Vec<u8>, Vec<u8>>,
}

fn main() -> Result<()> {
    let matches = clap_app!(tfa =>
        (version: "1.0")
        (author: "ururu. <mail@nyaa.gg>")
        (about: "Rusty Command-Line Two-Factor Authentication Utility")
        (@arg CLIPBOARD: ... --clip "Copy code to clipboard")
        (@arg CONFIG: -c --config +takes_value "Use a custom config file")
        (@arg HOTP: ... --hotp +takes_value "Generate HOTP with arguments as counters")
        (@arg LENGTH: -l --length +takes_value "Set the length of OTP code")
        (@arg INPUT:)
        (@subcommand add =>
            (about: "Add new service key to list")
            (@arg NAME: +required "<Your service name>")
            (@arg KEY: +required "<Service secret key>")
        )
        (@subcommand rm =>
            (about: "Delete service key from list")
            (@arg NAME: +required "<Your service name>")
        )
        (@subcommand list =>
            (about: "Show the all service name from list")
            (@arg SHOW_OTP_CODE: -s --show "Show the OTP code of service name")
        )
        (@subcommand master =>
            (about: "Configuration the master key for tfa-rs")
            (@arg KEY: +required "<Your master key>")
        )
        (@subcommand reset =>
            (about: "reset")
        )
    )
    .get_matches();

    let xdg_config_dir = if let Ok(dir) = std::env::var("XDG_CONFIG_DIR") {
        PathBuf::from(dir)
    } else {
        if let Some(pathbuf) = home_dir() {
            pathbuf.join(".config")
        } else {
            bail!("Could not found $XDG_CONFIG_DIR or $HOME. Please set the path to either env var.")
        }
    };

    let config_path = if let Some(config_path) = &matches.value_of("CONFIG") {
        Path::new(config_path).to_path_buf()
    } else {
        xdg_config_dir.join(".tfa")
    };

    if !config_path.exists() {
        let def = Config::default();
        save_config(&def, &config_path)?;
    }

    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&config_path)?;

    let mut config: Config = from_reader(f)?;

    if let Some(service_name) = &matches.value_of("INPUT") {
        let length = if let Some(len) = &matches.value_of("LENGTH") {
            usize::from_str_radix(len, 10)?
        } else {
            6 as usize
        };

        let code = get(
            &config,
            service_name,
            length,
            matches.value_of("HOTP").clone(),
        )?;
        println!("{}", &code);

        if matches.is_present("CLIPBOARD") {
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents(code.clone()).unwrap();
            println!("copy code to clipboard");
        }

        return Ok(());
    }

    if let Some(ref matches) = matches.subcommand_matches("add") {
        add(
            &mut config,
            &matches.value_of("NAME").unwrap(),
            matches.value_of("KEY").unwrap(),
        )?;
    }

    if let Some(ref matches) = matches.subcommand_matches("rm") {
        rm(&mut config, &matches.value_of("NAME").unwrap())?;
    }

    if let Some(ref matches) = matches.subcommand_matches("list") {
        list(&mut config, matches.is_present("SHOW_OTP_CODE"))?;
    }

    if let Some(ref matches) = matches.subcommand_matches("master") {
        master(&mut config, &matches.value_of("KEY").unwrap())?;
    }

    if let Some(_) = matches.subcommand_matches("reset") {
        reset(&config_path)?;
        println!("success to reset list");
        return Ok(());
    }

    save_config(&config, &config_path)?;

    Ok(())
}

pub fn save_config(config: &Config, path: &Path) -> Result<()> {
    let pretty = PrettyConfig::new();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)?;
    f.write_all(to_string_pretty(config, pretty)?.as_bytes())?;
    f.flush()?;
    Ok(())
}

pub fn get(config: &Config, name: &str, length: usize, counter: Option<&str>) -> Result<String> {
    let master_hash = config.master.to_string();
    let master_key = if &master_hash != "" {
        let password = prompt_password_stdout("Enter the master key: ")?;
        if verify_master_hash(&master_hash, &password).is_ok() {
            password.to_string()
        } else {
            bail!("Master key is wrong.\nif forget master key, need to reset list.")
        }
    } else {
        "".to_string()
    };

    if &master_key == "" {
        if !config.key_map.contains_key(name.as_bytes()) {
            bail!(format!("{} is not exists in list", name))
        }

        let value = config.key_map.get(name.as_bytes()).unwrap();
        let service_secret_key = String::from_utf8_lossy(&value);

        if let Some(counter) = counter {
            let c = u64::from_str_radix(counter, 16)?;
            tfa_hotp(c, &service_secret_key, length)
        } else {
            tfa_totp(&service_secret_key, length)
        }
    } else {
        let encrypted_name = encrypt(&master_key, name.as_bytes())?;

        if !config.key_map.contains_key(&encrypted_name) {
            bail!(format!("{} is not exists in list", name))
        }

        let value = config.key_map.get(&encrypted_name).unwrap();
        let decrypted = decrypt(&master_key, value)?;
        let service_secret_key = String::from_utf8_lossy(&decrypted);

        if let Some(counter) = counter {
            let c = u64::from_str_radix(counter, 16)?;
            tfa_hotp(c, &service_secret_key, length)
        } else {
            tfa_totp(&service_secret_key, length)
        }
    }
}

pub fn add(config: &mut Config, name: &str, key: &str) -> Result<()> {
    let master_hash = config.master.to_string();
    let master_key = if &master_hash != "" {
        let password = prompt_password_stdout("Enter the master key: ")?;
        if verify_master_hash(&master_hash, &password).is_ok() {
            password.to_string()
        } else {
            bail!("Master key is wrong.\nif forget master key, need to reset list.")
        }
    } else {
        "".to_string()
    };

    if &master_key == "" {
        if config.key_map.contains_key(name.as_bytes()) {
            bail!(format!("{} is already exists in list", name))
        }

        config
            .key_map
            .insert(name.as_bytes().to_vec(), key.as_bytes().to_vec());
    } else {
        let encrypted_name = encrypt(&master_key, name.as_bytes())?;

        if config.key_map.contains_key(&encrypted_name) {
            bail!(format!("{} is already exists in list", name))
        }

        let encrypted_key = encrypt(&master_key, key.as_bytes())?;
        config.key_map.insert(encrypted_name, encrypted_key);
    }

    Ok(())
}

pub fn rm(config: &mut Config, name: &str) -> Result<()> {
    let master_hash = config.master.to_string();
    let master_key = if &master_hash != "" {
        let password = prompt_password_stdout("Enter the master key: ")?;
        if verify_master_hash(&master_hash, &password).is_ok() {
            password.to_string()
        } else {
            bail!("Master key is wrong.\nif forget master key, need to reset list.")
        }
    } else {
        "".to_string()
    };

    if &master_key == "" {
        if !config.key_map.contains_key(name.as_bytes()) {
            bail!(format!("{} is not exists in list", name))
        }

        config.key_map.remove(name.as_bytes());
    } else {
        let encrypted_name = encrypt(&master_key, name.as_bytes())?;

        if !config.key_map.contains_key(&encrypted_name) {
            bail!(format!("{} is already exists in list", name))
        }

        config.key_map.remove(&encrypted_name);
    }

    Ok(())
}

pub fn list(config: &Config, show_otp_code: bool) -> Result<()> {
    let master_hash = config.master.to_string();
    let master_key = if &master_hash != "" {
        let password = prompt_password_stdout("Enter the master key: ")?;
        if verify_master_hash(&master_hash, &password).is_ok() {
            password.to_string()
        } else {
            bail!("Master key is wrong.\nif forget master key, need to reset list.")
        }
    } else {
        "".to_string()
    };

    if &master_key == "" {
        for (k, v) in config.key_map.iter() {
            if show_otp_code {
                let service_secret_key = String::from_utf8_lossy(v);
                println!("{}: {}", u8_to_string(k), tfa_totp(&service_secret_key, 6)?);
            } else {
                println!("{}", u8_to_string(k));
            }
        }
    } else {
        for (k, v) in config.key_map.iter() {
            if show_otp_code {
                let decrypted_name = decrypt(&master_key, k)?;
                let decrypted_key = decrypt(&master_key, v)?;
                let service_secret_key = String::from_utf8_lossy(&decrypted_key);
                println!("{}: {}", u8_to_string(&decrypted_name), tfa_totp(&service_secret_key, 6)?);
            } else {
                let decrypted_name = decrypt(&master_key, k)?;
                println!("{}", u8_to_string(&decrypted_name));
            }
        }
    }

    Ok(())
}

pub fn master(config: &mut Config, key: &str) -> Result<()> {
    if config.master != "" {
        bail!("Master key is already exists")
    }

    let master_hash = get_master_hash(key)?;

    config.master = master_hash;

    let mut new_key_map = HashMap::new();

    for (k, v) in config.key_map.iter() {
        let encrypted_name = encrypt(key, k)?;
        let encrypted_key = encrypt(key, &v)?;
        new_key_map.insert(encrypted_name, encrypted_key);
    }

    config.key_map = new_key_map;

    println!("Success to set master key.\nif forget master key, need to reset list.");

    Ok(())
}

pub fn reset(config_path: &PathBuf) -> Result<()> {
    let def = Config::default();
    save_config(&def, &config_path)?;
    Ok(())
}

pub fn encrypt(key: &str, value: &[u8]) -> Result<Vec<u8>> {
    let mut g_key = GLOBAL_KEY.clone();
    let key = key.as_bytes();

    for (i, k) in key.iter().enumerate() {
        if i == 32 {
            break;
        }
        g_key[i] = *k;
    }

    let key = Key::from_slice(&g_key);
    let nonce = Nonce::from_slice(b"tfa-rs nonce");
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.encrypt(nonce, value);

    match ciphertext {
        Ok(vec) => Ok(vec),
        Err(e) => bail!(e.to_string()),
    }
}

pub fn decrypt(key: &str, value: &[u8]) -> Result<Vec<u8>> {
    let mut g_key = GLOBAL_KEY.clone();
    let key = key.as_bytes();

    for (i, k) in key.iter().enumerate() {
        if i == 32 {
            break;
        }
        g_key[i] = *k;
    }

    let key = Key::from_slice(&g_key);
    let nonce = Nonce::from_slice(b"tfa-rs nonce");
    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher.decrypt(nonce, value);

    match ciphertext {
        Ok(vec) => Ok(vec),
        Err(e) => bail!(e.to_string()),
    }
}

pub fn get_master_hash(password: &str) -> Result<String> {
    let password = password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 =
        Argon2::new(None, 1, 1024 * 1024 * 37, 1, Version::default()).map_err(Error::msg)?;
    let password_hash = argon2
        .hash_password_simple(password, salt.as_ref())
        .map_err(Error::msg)?
        .to_string();
    let parsed_hash = PasswordHash::new(&password_hash).map_err(Error::msg)?;

    match argon2.verify_password(password, &parsed_hash) {
        Ok(_) => Ok(password_hash),
        Err(e) => bail!(e.to_string()),
    }
}

pub fn verify_master_hash(password_hash: &str, password: &str) -> Result<()> {
    let password = password.as_bytes();
    let argon2 =
        Argon2::new(None, 1, 1024 * 1024 * 37, 1, Version::default()).map_err(Error::msg)?;
    let parsed_hash = PasswordHash::new(&password_hash).map_err(Error::msg)?;

    argon2
        .verify_password(password, &parsed_hash)
        .map_err(Error::msg)
}

pub fn tfa_totp(key: &str, len: usize) -> Result<String> {
    let code = TOTPBuilder::new()
        .base32_key(key)
        .output_len(len)
        .finalize();

    if let Ok(code) = code {
        Ok(code.generate())
    } else {
        bail!("Could not get OTP code")
    }
}

pub fn tfa_hotp(counter: u64, key: &str, len: usize) -> Result<String> {
    let code = HOTPBuilder::new()
        .base32_key(key)
        .counter(counter)
        .output_len(len)
        .finalize();

    if let Ok(code) = code {
        Ok(code.generate())
    } else {
        bail!("Could not get OTP code")
    }
}

pub fn u8_to_string(bin: &[u8]) -> String {
    String::from_utf8_lossy(bin).to_string()
}
