use std::fs;
use std::sync::Arc;
use std::thread::sleep;
use epi::App;
use eframe::{egui, epi};
use egui::{Color32, Stroke, stroke_ui, vec2};
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
    selected: String,
    input_encrypted_text: String,
}

impl App for MyApp {
    fn name(&self) -> &str {
        "RheinSec-GUI"
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &mut epi::Frame<'_>) {
        ctx.set_visuals(egui::Visuals::light());
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.vertical_centered(|ui| {


            ui.visuals_mut().dark_mode = false;
            ui.style_mut().visuals.button_frame = true;
            ui.style_mut().visuals.widgets.inactive.bg_fill = Color32::from_rgb(0, 0, 255);
            ui.style_mut().visuals.override_text_color = Some(Color32::from_rgb(255, 255, 255));
            ui.add_space(5.0);
            ui.visuals_mut().widgets.inactive.fg_stroke = Stroke::new(1.0, Color32::from_rgb(255, 255, 255));
            ui.style_mut().body_text_style = egui::TextStyle::Heading;
            ui.style_mut().override_text_style = Option::from(egui::TextStyle::Heading);

                    ui.horizontal(|ui| {
                        // Dynamically calculate the space needed to center the combo box every time the UI is drawn
                        let available_width = ui.available_width();
                        let space_before = (available_width - 492.0) / 2.0;
                        ui.add_space(space_before.max(0.0)); // Ensure there's no negative space

                        egui::ComboBox::from_id_source("Select algorithm")
                            .width(492.0)
                            .selected_text("Select algorithm")
                            .show_ui(ui, |ui| {
                                let previous_selected = self.selected.clone();
                                ui.selectable_value(&mut self.selected, "AES".to_string(), "AES");
                                ui.selectable_value(&mut self.selected, "RSA".to_string(), "RSA");
                                ui.selectable_value(&mut self.selected, "ECDH".to_string(), "ECDH");
                                ui.selectable_value(&mut self.selected, "ECDSA".to_string(), "ECDSA");
                                if previous_selected != self.selected {
                                    deltoken();
                                    self.output.clear();
                                }
                            });
                    });

                    ui.style_mut().visuals.override_text_color = Some(Color32::from_rgb(255, 255, 255));
            ui.add_space(10.0);

            if(&self.selected == "AES") {

                if ui.add_sized([500.0, 40.0], egui::Button::new("Generate AES key")).clicked(){
                    ctx.request_repaint();
                    create_aes_key_gui();
                    self.output.clear();
                    self.output.push_str("AES keys generated!");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Load AES key")).clicked() {
                    ctx.request_repaint();
                    self.aes_key = load_aes_key_gui().unwrap();
                    self.output.clear();
                    self.output.push_str(&self.aes_key);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                //ui.add_sized([500.0, 40.0], egui::Label::new("test123").text_color(egui::Color32::from_rgb(0, 0, 0)));
                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the Data that should be encrypted");
                ui.add_sized([500.0, 40.0], egui::TextEdit::singleline(&mut self.input_encrypt_text));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Encrypt AES")).clicked() {
                    ctx.request_repaint();
                    self.encrypted_data_rsa = "Input data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text, SymmetricMode::Ccm, &[KeyBits::Bits128, KeyBits::Bits192, KeyBits::Bits256]).unwrap().0;
                    self.output.clear();
                    self.output.push_str(&self.encrypted_data_aes);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.encrypted_data_aes = "Encrypted data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text, SymmetricMode::Cbc, &[KeyBits::Bits128]).unwrap().1;
                    self.output.push_str(&self.encrypted_data_aes_base64);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                    ui.add_space(10.0);
                    ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                    ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the encrypted String");
                    ui.add_sized([500.0, 40.0], egui::TextEdit::singleline(&mut self.input_encrypted_text));
                    ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                    ui.add_space(10.0);

                    if ui.add_sized([500.0, 40.0], egui::Button::new("Decrypt AES")).clicked(){
                        self.decrypted_data_aes = "Decrypted Data: ".to_owned() + &*encrypt_and_decrypt_aes_gui(&self.input_encrypt_text,SymmetricMode::Ccm,&[KeyBits::Bits128]).unwrap().2;
                        self.output.clear();
                        self.output.push_str(&self.decrypted_data_aes);
                    };

                    ui.add_space(10.0);
                    ui.colored_label(egui::Color32::from_rgb(0, 0, 0),&mut self.output);
            }


            if(self.selected == "RSA"){

                if ui.add_sized([500.0, 40.0], egui::Button::new("Generate RSA key")).clicked() {
                    create_rsa_key_gui();
                    self.output.clear();
                    self.output.push_str("RSA keys generated!");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Load RSA key")).clicked() {
                    ctx.request_repaint();
                    self.rsa_key = load_rsa_key_gui().unwrap();
                    self.output.clear();
                    self.output.push_str(&self.rsa_key);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the Data that should be encrypted");
                ui.add_sized([500.0, 20.0], egui::TextEdit::singleline(&mut self.input_encrypt_text));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Sign RSA")).clicked(){
                    ctx.request_repaint();
                    self.output.clear();
                    let full_signature = sign_and_verifiy_rsa_gui(&self.input_encrypt_text).unwrap().1;
                    let max_length = 80;
                    if full_signature.len() > max_length {
                        let start = &full_signature[0..40];
                        let end = &full_signature[(full_signature.len()-40)..];
                        self.sign_data_rsa = format!("Signature: {} ..... {}", start, end);
                    } else {
                        self.sign_data_rsa = "Signature: ".to_owned() + &full_signature;
                    }
                    self.output.push_str(&self.sign_data_rsa);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };
                ui.add_space(10.0);
                if ui.add_sized([500.0, 40.0], egui::Button::new("Verify RSA")).clicked(){
                    ctx.request_repaint();

                    let verification_result = sign_and_verifiy_rsa_gui(&self.input_encrypt_text).unwrap().0;
                    if verification_result {
                        self.output.clear();
                        self.output.push_str(&format!("Signature verified successfully! input text: {}", self.input_encrypt_text));
                    } else {
                        self.output.clear();
                        self.output.push_str("Signature verification failed!");
                    }
                };
                ui.add_space(10.0);
                if ui.add_sized([500.0, 40.0], egui::Button::new("Encrypt RSA")).clicked(){
                    ctx.request_repaint();
                    self.encrypted_data_rsa = "Input data: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().0;
                    self.output.clear();
                    self.output.push_str(&self.encrypted_data_rsa);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.encrypted_data_rsa_base64 = "Encrypted data: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().1;
                    self.output.push_str(&self.encrypted_data_rsa_base64);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the encrypted String");
                let mut encrypted_data_without_prefix = self.encrypted_data_rsa_base64.replace("Encrypted data: ", "");
                ui.add_sized([500.0, 20.0], egui::TextEdit::singleline(&mut encrypted_data_without_prefix));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Decrypt RSA")).clicked(){
                    self.decrypted_data_rsa = "Decrypted data: ".to_owned() + &*encrypt_and_decrypt_rsa_gui(&self.input_encrypt_text).unwrap().2;
                    self.output.clear();
                    self.output.push_str(&self.decrypted_data_rsa);
                };

                ui.add_space(10.0);

                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),&mut self.output);
            }


            if(self.selected == "ECDH"){

                if ui.add_sized([500.0, 40.0], egui::Button::new("Generate ECDH key")).clicked() {
                    ctx.request_repaint();
                    create_ecdh_key_gui();
                    self.output.push_str("ECDH keys generated!");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Load ECDH")).clicked() {
                    ctx.request_repaint();
                    self.ecdh_key = load_ecdh_key_gui().unwrap();
                    self.output.push_str(&self.ecdh_key);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the Data that should be encrypted");
                ui.add_sized([500.0, 20.0], egui::TextEdit::singleline(&mut self.input_encrypt_text));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);


                if ui.add_sized([500.0, 40.0], egui::Button::new("Encrypt ECDH")).clicked() {
                    ctx.request_repaint();
                    self.encrypted_data_ecdh = "Input data: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().0;
                    self.output.push_str(&self.encrypted_data_ecdh);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.show_encrypt_edch_data = true;
                    self.encrypted_data_ecdh_base64 = "Encrypted daten: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().1;
                    self.output.push_str(&self.encrypted_data_ecdh_base64);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the encrypted String");
                ui.add_sized([500.0, 20.0], egui::TextEdit::singleline(&mut self.input_encrypted_text));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Decrypt ECDH")).clicked(){
                    ctx.request_repaint();
                    self.decrypted_data_ecdh = "Decrypted data: ".to_owned() + &*encrypt_and_decrypt_ecdh_gui(&self.input_encrypt_text).unwrap().2;
                    self.output.push_str(&self.decrypted_data_ecdh);
                };

                ui.add_space(10.0);

                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),&mut self.output);
            }

            if(self.selected == "ECDSA"){

                if ui.add_sized([500.0, 40.0], egui::Button::new("generate ECDSA keys")).clicked() {
                    ctx.request_repaint();
                    create_ecdsa_key_gui();
                    self.output.push_str("ECDSA keys generated!");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Load ECDSA")).clicked(){
                    ctx.request_repaint();
                    self.ecdsa_key = load_ecdsa_key_gui().unwrap();
                    self.output.push_str(&self.ecdsa_key);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(0, 0, 0));
                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),"Please provide the Data that should be encrypted");
                ui.add_sized([500.0, 20.0], egui::TextEdit::singleline(&mut self.input_encrypt_text));
                ui.visuals_mut().override_text_color = Some(egui::Color32::from_rgb(255, 255, 255));
                ui.add_space(10.0);

                if ui.add_sized([500.0, 40.0], egui::Button::new("Sign ECDSA")).clicked(){
                    ctx.request_repaint();
                    self.sign_data_ecdsa = "Signature verified: ".to_owned() + &*sign_and_verifiy_ecdsa_gui(&self.input_encrypt_text).unwrap().0.to_string();
                    self.output.push_str(&self.sign_data_ecdsa);
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.sign_data_ecdsa = "Signature: ".to_owned() + &*sign_and_verifiy_ecdsa_gui(&self.input_encrypt_text).unwrap().1;
                    self.output.push_str(&self.sign_data_ecdsa);
                    self.show_sign_ecdsa_str=true;
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                    self.output.push_str("\n");
                };

                ui.add_space(10.0);

                ui.colored_label(egui::Color32::from_rgb(0, 0, 0),&mut self.output);
            }
                });
            });
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
        selected: "".to_string(),
        input_encrypted_text: "".to_string(),
    };
    deltoken();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(app), native_options);
}
fn deltoken() {
    let file_path = "token.json";
    println!("Deleting token file: {:?}", file_path);
    if fs::metadata(file_path).is_ok() {
        fs::remove_file(file_path);
    }
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
            "https://141.19.143.81/".to_string(),
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
            "https://141.19.143.81/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519))),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
            None,
        )),
        "ecdh" => Some(NksConfig::new(
            "".to_string(),
            "https://141.19.143.81/".to_string(),
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
                "https://141.19.143.81/".to_string(),
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
                    let mut public_key = key.get("publicKey").unwrap().as_str().unwrap().to_string();
                    let  mut private_key = key.get("privateKey").unwrap().as_str().unwrap().to_string();

                    if key_id == "test_rsa_key" {
                        // Schneiden Sie den öffentlichen Schlüssel auf die ersten 20 Zeichen ab
                        public_key = public_key.chars().take(150).collect::<String>();
                        private_key = private_key.chars().take(150).collect::<String>();
                    }

                    return Ok((private_key, public_key));
                }
            }
        }
    }
    Err(serde_json::Error::custom("secrets_json is None"))
}