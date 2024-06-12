use std::sync::Arc;
use std::thread::sleep;
use epi::App;
use eframe::{egui, epi};
use egui::Color32;
use serde::de::Error;
use crate::common::traits::key_handle::KeyHandle;
use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm, SymmetricMode};
use crate::common::crypto::algorithms::hashes::{Hash, Sha2Bits};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::crypto::KeyUsage;
use crate::common::traits::module_provider::Provider;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::common::error::SecurityModuleError;
use crate::nks::hcvault::NksProvider;
use crate::nks::NksConfig;
pub mod common;
pub mod nks;

struct MyApp {
    show_text_AES_create: bool,
    show_text_RSA_create: bool,
    show_text_ECDH_create: bool,
    show_text_ECDSA_create: bool,
    show_text_AES_load: bool,
    show_text_RSA_load: bool,
    show_text_RSA_load_test:  bool,
    show_text_ECDH_load: bool,
    show_text_ECDSA_load: bool,
    show_sign_rsa_bool: bool,
    show_sign_rsa_str: bool,
    show_sign_ecdsa_bool: bool,
    show_sign_ecdsa_str: bool,
    input_encrypt_text: String,
    show_decrypt_aes: bool,
    show_encrypt_rsa: bool,
    show_encrypt_rsa_data: bool,
    show_decrypt_rsa: bool,
    show_encrypt_aes: bool,
    show_encrypt_ecdh: bool,
    show_encrypt_edch_data: bool,
    show_decrypt_ecdh: bool,
    aes_key: String,
    rsa_key: String,
    ecdh_key: String,
    ecdsa_key: String,
    sign_data_rsa: String,
    sign_data_ecdsa: String,
    encrypted_data_aes: String,
    encrypted_data_aes_base64: String,
    encrypted_data_rsa: String,
    encrypted_data_rsa_base64: String,
    encrypted_data_ecdh: String,
    encrypted_data_ecdh_base64: String,
    decrypted_data_aes: String,
    decrypted_data_rsa: String,
    decrypted_data_ecdh: String,
    output: String,
}

impl App for MyApp {
    fn name(&self) -> &str {
        "ECDSA-Test"
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &mut epi::Frame<'_>) {
        ctx.set_visuals(egui::Visuals::light());
        egui::CentralPanel::default().show(ctx, |ui| {
//            ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
            ui.visuals_mut().dark_mode = false;
            ui.style_mut().visuals.button_frame = true;
            ui.style_mut().visuals.widgets.inactive.bg_fill = Color32::from_rgb(0, 0, 255);
//           ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Bitte geben Sie den Text ein der Verschlüsselt werden soll:");
//            ui.text_edit_singleline(&mut self.input_encrypt_text);
            ui.style_mut().visuals.override_text_color = Some(Color32::from_rgb(255, 255, 255));
            ui.add_space(5.0);

                       if ui.button("AES Schlüssel erzeugen").clicked() {
                           ctx.request_repaint();
                           create_aes_key_gui();
                           self.output.push_str("AES Schlüssel wurden erzeugt!");
                           self.output.push_str("\n");
                           self.output.push_str("\n");
                           self.output.push_str("\n");
                        }

                        ui.add_space(10.0);

                        if ui.button("AES Schlüssel laden").clicked() {
                            ctx.request_repaint();
                            self.aes_key = load_aes_key_gui().unwrap();
                            self.output.push_str(&self.aes_key);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }

            ui.add_space(10.0);
/*
            //RSA
            if ui.button("RSA Schlüssel erzeugen").clicked() {
                create_rsa_key_gui();
                self.output.push_str("RSA Schlüssel wurden erzeugt!");
                self.output.push_str("\n");
                self.output.push_str("\n");
            }

            ui.add_space(10.0);

            if ui.button("RSA Schlüssel laden").clicked() {
                ctx.request_repaint();
                self.rsa_key = load_rsa_key_gui().unwrap();
                self.output.push_str(&self.rsa_key);
                self.output.push_str("\n");
                self.output.push_str("\n");
            }

            ui.add_space(10.0);
            //RSA

                        //ECDH
                        if ui.button("ECDH Schlüssel erzeugen").clicked() {
                            ctx.request_repaint();
                            create_ecdh_key_gui();
                            self.output.push_str("ECDH Schlüssel wurden erzeugt!");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }

                        ui.add_space(10.0);

                        if ui.button("ECDH Schlüssel laden").clicked() {
                            ctx.request_repaint();
                            self.ecdh_key = load_ecdh_key_gui().unwrap();
                            self.output.push_str(&self.ecdh_key);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }



                        //ECDSA
                        if ui.button("ECDSA Schlüssel erzeugen").clicked() {
                            ctx.request_repaint();
                            create_ecdsa_key_gui();
                            self.output.push_str("ECDSA Schlüssel wurden erzeugt!");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }

                        ui.add_space(10.0);

                        if ui.button("ECDSA Schlüssel laden").clicked(){
                            ctx.request_repaint();
                            self.ecdsa_key = load_ecdsa_key_gui().unwrap();
                            self.output.push_str(&self.ecdsa_key);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }

*/
            ui.add_space(10.0);
            ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
            ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Bitte geben Sie den Text ein der Verschlüsselt werden soll:");
            ui.text_edit_singleline(&mut self.input_encrypt_text);
            ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
            ui.add_space(10.0);
/*
            //sign
            if ui.button("RSA Signieren").clicked(){
                ctx.request_repaint();
                self.sign_data_rsa = "Signatur überprüfung erfolgreich: ".to_owned() + &*sign_and_verifiy_rsa_gui(&self.input_encrypt_text).unwrap().0.to_string();
                self.output.push_str(&self.sign_data_rsa);
                self.output.push_str("\n");
                self.output.push_str("\n");
                self.sign_data_rsa = "Signatur: ".to_owned() + &*sign_and_verifiy_rsa_gui(&self.input_encrypt_text).unwrap().1;
                self.output.push_str(&self.sign_data_rsa);
                self.output.push_str("\n");
                self.output.push_str("\n");
                self.output.push_str("\n");
            }

//            ui.add_space(10.0);

                        if ui.button("ECDSA Signieren").clicked(){
                            ctx.request_repaint();
                            self.sign_data_ecdsa = "Signatur überprüfung erfolgreich: ".to_owned() + &*sign_and_verifiy_ecdsa_gui(&self.input_encrypt_text).unwrap().0.to_string();
                            self.output.push_str(&self.sign_data_ecdsa);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.sign_data_ecdsa = "Signatur: ".to_owned() + &*sign_and_verifiy_ecdsa_gui(&self.input_encrypt_text).unwrap().1;
                            self.output.push_str(&self.sign_data_ecdsa);
                            self.show_sign_ecdsa_str=true;
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }


                        ui.add_space(10.0);
*/
                        //encrypt
                        if ui.button("AES Verschlüsseln").clicked(){
                            ctx.request_repaint();
                            self.encrypted_data_rsa = "Input Data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text, SymmetricMode::Ccm, &[KeyBits::Bits128,KeyBits::Bits192,KeyBits::Bits256]).unwrap().0;
                            self.output.push_str(&self.encrypted_data_aes);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.encrypted_data_aes = "Encrypted Data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text, SymmetricMode::Cbc,&[KeyBits::Bits128]).unwrap().1;
                            self.output.push_str(&self.encrypted_data_aes_base64);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");

                        }


            ui.add_space(10.0);
/*
            if ui.button("RSA Verschlüsseln").clicked(){
                ctx.request_repaint();
                self.encrypted_data_rsa = "Input Daten: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().0;
                self.output.push_str(&self.encrypted_data_rsa);
                self.output.push_str("\n");
                self.output.push_str("\n");
                self.encrypted_data_rsa_base64 = "Verschlüsselte Daten: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().1;
                self.output.push_str(&self.encrypted_data_rsa_base64);
                self.output.push_str("\n");
                self.output.push_str("\n");
                self.output.push_str("\n");
            }


                        //ui.add_space(10.0);

                        if ui.button("ECDH Verschlüsseln").clicked(){
                            ctx.request_repaint();
                            self.encrypted_data_ecdh = "Input Daten: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().0;
                            self.output.push_str(&self.encrypted_data_ecdh);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.show_encrypt_edch_data=true;
                            self.encrypted_data_ecdh_base64 = "Verschlüsselte Daten: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().1;
                            self.output.push_str(&self.encrypted_data_ecdh_base64);
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                            self.output.push_str("\n");
                        }

                        ui.add_space(10.0);
*/
                        //decrypt
                        if ui.button("Decrypt AES").clicked(){
                            self.decrypted_data_aes = "Decrypted Data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text,SymmetricMode::Ccm,&[KeyBits::Bits128]).unwrap().2;
                            self.output.push_str(&self.decrypted_data_aes);
                        }
/*
            ui.add_space(10.0);

            if ui.button("RSA Entschlüsseln").clicked(){
                self.decrypted_data_rsa = "Entschlüsselte Daten: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().2;
                self.output.push_str(&self.decrypted_data_rsa);
            }

            ui.add_space(10.0);

                        if ui.button("ECDH Entschlüsseln").clicked(){
                            ctx.request_repaint();
                            self.decrypted_data_ecdh = "Entschlüssete Daten: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().2;
                            self.output.push_str(&self.decrypted_data_ecdh);
                        }
*/
            ui.add_space(10.0);

            ui.colored_label(egui::Color32::from_rgb(0, 0, 0),&self.output);
        });
    }
}

fn main() {
    let app = MyApp {
        show_text_AES_create: false,
        show_text_AES_load: false,
        show_text_RSA_create: false,
        show_text_RSA_load: false,
        show_text_RSA_load_test: false,
        show_text_ECDH_create: false,
        show_text_ECDH_load: false,
        show_text_ECDSA_create: false,
        show_text_ECDSA_load: false,
        show_sign_rsa_bool: false,
        show_sign_rsa_str: false,
        show_sign_ecdsa_bool: false,
        show_sign_ecdsa_str: false,
        input_encrypt_text: "".to_string(),
        show_encrypt_aes: false,
        show_decrypt_aes: false,
        show_encrypt_rsa: false,
        show_encrypt_rsa_data: false,
        show_decrypt_rsa: false,
        show_encrypt_ecdh: false,
        show_encrypt_edch_data: false,
        show_decrypt_ecdh: false,
        aes_key: "".to_string(),
        rsa_key: "".to_string(),
        ecdh_key: "".to_string(),
        ecdsa_key: "".to_string(),
        sign_data_rsa: "".to_string(),
        sign_data_ecdsa: "".to_string(),
        encrypted_data_aes: "".to_string(),
        encrypted_data_aes_base64: "".to_string(),
        encrypted_data_rsa: "".to_string(),
        encrypted_data_rsa_base64: "".to_string(),
        encrypted_data_ecdh: "".to_string(),
        encrypted_data_ecdh_base64: "".to_string(),
        decrypted_data_aes: "".to_string(),
        decrypted_data_rsa: "".to_string(),
        decrypted_data_ecdh: "".to_string(),
        output: "".to_string(),
    };
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(app), native_options);
}

fn create_aes_key_gui() {
    for &key_size in &[KeyBits::Bits128, KeyBits::Bits192, KeyBits::Bits256] {
        for &aes_mode in &[SymmetricMode::Gcm, SymmetricMode::Ecb, SymmetricMode::Cbc, SymmetricMode::Ctr, SymmetricMode::Cfb, SymmetricMode::Ofb] {
            let mut provider = NksProvider::new("test_key".to_string());

            provider.config = Some(get_config("aes", Some(key_size), Some(aes_mode)).unwrap());

            provider
                .initialize_module()
                .expect("Failed to initialize module");

            if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
                provider
                    .create_key(&format!("test_aes_key_{}_{}", aes_mode as u8, key_size as u8), Box::new(nks_config.clone()))
                    .expect("Failed to create AES key");
            } else {
                println!("Failed to downcast to NksConfig");
            }
        }
    }
}

fn create_rsa_key_gui() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to create RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

fn create_ecdh_key_gui() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdh", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_ecdh_key", Box::new(nks_config.clone()))
            .expect("Failed to create ECDH key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

fn create_ecdsa_key_gui() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdsa", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to create ECDSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

fn load_aes_key_gui() ->Result<String, SecurityModuleError>{
    let mut key = "".to_string();
    for &key_size in &[KeyBits::Bits128, KeyBits::Bits192, KeyBits::Bits256] {
        for &aes_mode in &[SymmetricMode::Gcm, SymmetricMode::Ccm, SymmetricMode::Ecb, SymmetricMode::Cbc, SymmetricMode::Ctr, SymmetricMode::Cfb, SymmetricMode::Ofb] {
            let mut provider = NksProvider::new("test_key".to_string());

            provider.config = Some(get_config("aes", Some(key_size), Some(aes_mode)).unwrap());

            provider
                .initialize_module()
                .expect("Failed to initialize module");

            if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
                provider
                    .load_key(&format!("test_aes_key_{}_{}", aes_mode as u8, key_size as u8), Box::new(nks_config.clone()))
                    .expect("Failed to load AES key");
                key = format!("Private Key: {:?}\n", extract_keys_from_secrets(&provider, "test_aes_key_0_0").unwrap().0);
            } else {
                println!("Failed to downcast to NksConfig");
            }
        }
    }
    //let key_string = String::from_utf8(&key).expect("Failed to convert key to string");
    if (1 == 1) {
        Ok(key)
    } else {
        Err(SecurityModuleError::NksError)
    }
}

fn load_rsa_key_gui() -> Result<String, SecurityModuleError> {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        let keys = provider
            .load_key("test_rsa_key", Box::new(nks_config.clone()))?;
        let keys_string = format!("Private Key: {:?}\n\nPublic Key: {:?}\n", extract_keys_from_secrets(&provider, "test_rsa_key").unwrap().0, extract_keys_from_secrets(&provider, "test_rsa_key").unwrap().1);

        Ok(keys_string)
    } else {
        println!("Failed to downcast to NksConfig");
        Err(SecurityModuleError::NksError)
    }
}

fn load_ecdsa_key_gui() -> Result<String, SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdsa", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        let keys = provider
            .load_key("test_ecdsa_key", Box::new(nks_config.clone()))?;
        let keys_string = format!("Private Key: {:?}\n\nPublic Key: {:?}", extract_keys_from_secrets(&provider, "test_ecdsa_key").unwrap().0, extract_keys_from_secrets(&provider, "test_ecdsa_key").unwrap().1);
        Ok(keys_string)
    } else {
        println!("Failed to downcast to NksConfig");
        Err(SecurityModuleError::NksError)
    }
}

fn load_ecdh_key_gui() -> Result<String, SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdh", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        let keys = provider
            .load_key("test_ecdh_key", Box::new(nks_config.clone()))?;
        let keys_string = format!("Private Key: {:?}\n\nPublic Key: {:?}", extract_keys_from_secrets(&provider, "test_ecdh_key").unwrap().0, extract_keys_from_secrets(&provider, "test_ecdh_key").unwrap().1);
        Ok(keys_string)
    } else {
        println!("Failed to downcast to NksConfig");
        Err(SecurityModuleError::NksError)
    }
}
fn sign_and_verifiy_rsa_gui(data: &str) -> Result<(bool, String), SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());
    provider.config = Some(get_config("rsa", None, None).unwrap());
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
    let data = data.as_bytes();
    let signature = provider.sign_data(data).expect(
        "Failed to sign data",
    );
    let signature_string = base64::encode(&signature);
    let result = provider.verify_signature(data, &signature).unwrap();
    Ok((result, signature_string))
}

fn sign_and_verifiy_ecdsa_gui(data: &str) -> Result<(bool, String), SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());
    provider.config = Some(get_config("ecdsa", None, None).unwrap());
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDSA Key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
    let data = data.as_bytes();
    let signature = provider.sign_data(data).expect(
        "Failed to sign data",
    );
    let signature_string = base64::encode(&signature);
    let result = provider.verify_signature(data, &signature).unwrap();
    Ok((result, signature_string))
}

fn encrypt_and_decrypt_aes_gui(data: &str, mode: SymmetricMode, key_sizes: &[KeyBits]) -> Result<(String, String, String), SecurityModuleError>{
    let decrypted_data = vec![];
    let encrypted_data = vec![];
    for &key_size in key_sizes {
        let mut provider = NksProvider::new(format!("aes_{}", mode as u8));
        provider.config = Some(get_config("aes", Some(key_size), Some(mode)).unwrap());
        provider.initialize_module().expect("Failed to initialize module");

        if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
            provider.load_key(&format!("test_aes_key_{}_{}", mode as u8, key_size as u8), Box::new(nks_config.clone()))
                .expect("Failed to load AES key");
        } else {
            println!("Failed to downcast to NksConfig");
        }

        let data = data.as_bytes();
        let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
        let decrypted_data = provider.decrypt_data(&encrypted_data).expect("Failed to decrypt data");
    }
    let decrypted_string = String::from_utf8(decrypted_data).map_err(|_| SecurityModuleError::NksError)?;
    let encrypted_string = base64::encode(&encrypted_data);
    return Ok((data.to_string(), encrypted_string, decrypted_string));
}
fn encrypt_and_decrypt_rsa_gui(data: &str) -> Result<(String, String, String), SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }

    let data = data.as_bytes();
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");
    let decrypted_string = String::from_utf8(decrypted_data).map_err(|_| SecurityModuleError::NksError)?;
    let encrypted_string = base64::encode(&encrypted_data);
    Ok((String::from_utf8(data.to_vec()).unwrap(),encrypted_string, decrypted_string))
}

fn encrypt_and_decrypt_ecdh_gui(data: &str) -> Result<(String, String, String), SecurityModuleError>{
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdh", None, None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_ecdh_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDH key");
    } else {
        println!("Failed to downcast to NksConfig");
    }

    let data = data.as_bytes();
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");
    let decrypted_string = String::from_utf8(decrypted_data).map_err(|_| SecurityModuleError::NksError)?;
    let encrypted_string = base64::encode(&encrypted_data);
    Ok((String::from_utf8(data.to_vec()).unwrap(), encrypted_string,decrypted_string))
}


pub fn get_config(key_type: &str, key_size: Option<KeyBits>, aes_mode: Option<SymmetricMode>) -> Option<Arc<dyn ProviderConfig + Send + Sync>> {
    match key_type {
        "rsa" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Rsa(2048.into())),
            Hash::Sha2(256.into()),
            vec![
                KeyUsage::ClientAuth,
                KeyUsage::Decrypt,
                KeyUsage::SignEncrypt,
                KeyUsage::CreateX509,
            ],
            None,
        )),
        "ecdsa" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519))),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
            None,
        )),
        "ecdh" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519))),
            Hash::Sha2(384.into()),
            vec![KeyUsage::Decrypt],
            None,
        )),
        "aes" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            let aes_mode = aes_mode.unwrap_or(SymmetricMode::Gcm); // Default to GCM mode if no mode is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(aes_mode, key_size)),
            ))
        },
        _ => None,
    }
}

fn extract_keys_from_secrets(provider: &NksProvider, key_id: &str) -> Result<(String, String), serde_json::Error> {
    // Überprüfen Sie, ob secrets_json vorhanden ist
    println!("secrets_json: {:?}", provider.secrets_json);
    if let Some(secrets) = &provider.secrets_json {
        // Iterate over the secrets_json object
        if let Some(keys) = secrets.get("keys") {
            for key in keys.as_array().unwrap() {
                // Check if the key_id matches
                if key.get("id").unwrap().as_str().unwrap() == key_id {
                    // Set the public_key and private_key
                    let public_key = key.get("publicKey").unwrap().as_str().unwrap().to_string();
                    let private_key = key.get("privateKey").unwrap().as_str().unwrap().to_string();
                    return Ok((private_key, public_key));
                }
            }
        }

        // Extrahieren Sie die
        let public_key= "".to_string();
        let private_key= "".to_string();
        if  (key_id == "test_rsa_key" || key_id == "test_ecdsa_key" || key_id == "test_ecdh_key"){
            let public_key = secrets.get("publicKey").unwrap().as_str().unwrap().to_string();
            let private_key = secrets.get("privateKey").unwrap().as_str().unwrap().to_string();
        } else {
            let private_key = secrets.get("privateKey").unwrap().as_str().unwrap().to_string();
        }

        Ok((public_key, private_key))
    } else {
        Err(serde_json::Error::custom("secrets_json is None"))
    }
}