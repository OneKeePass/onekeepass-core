use log::debug;
use serde::{Deserialize, Serialize};

use crate::error::Result;

use super::PasswordScore;

#[derive(Deserialize, Serialize, Debug)]
pub struct GeneratedPassPhrase {
    password: String,
    score: PasswordScore,
    entropy_bits: f64,
}

// Caller of pass phrase generator need to implement this
pub trait WordListLoader {
    fn load_from_resource(&self, file_name: &str) -> Result<String>;
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "type_name", content = "content")]
pub(crate) enum WordListSource {
    EFFLarge,
    EFFShort1,
    EFFShort2,
    Google10000UsaEnglishNoSwearsMedium,
    FrenchDicewareWordlist, //french-diceware-wordlist
    GermanDicewareWordlist,
    Custom(String),
}

impl WordListSource {
    fn name(&self) -> &str {
        debug!("Name fn is called for {:?}", &self);
        match self {
            Self::Google10000UsaEnglishNoSwearsMedium => {
                "google-10000-english-usa-no-swears-medium.txt"
            }
            Self::FrenchDicewareWordlist => "french-diceware-wordlist.txt",
            Self::GermanDicewareWordlist => "german-diceware-wordlist.txt",
            _ => "NoWordList",
        }
    }
}

// Similar to chbs::probability::Probability with serilaization support
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "type_name", content = "content")]
pub(crate) enum ProbabilityOption {
    /// This is always true.
    Always,

    /// This is sometimes true.
    ///
    /// If `1.0` it's always true, if `0.0` it is never true, the value may be anywhere in between.
    ///
    /// If the value is exactly `0.0` or `1.0` the variants [`Always`](Probability::Always) and
    /// [`Never`](Probability::Never) should be used instead.
    /// It is therefore recommended to construct this type using the
    /// [`from`](Probability::from) method as this automatically chooses the correct variant.
    ///
    /// This value may never be `p < 0` or `p > 1`, as it will cause panics.
    Sometimes(f64),

    /// This is never true, and is always false.
    Never,
}

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct PassphraseGenerationOptions {
    pub(crate) word_list_source: WordListSource,

    // No of words in the phrase
    pub words: usize,

    // The separator string to use between passphrase words.
    pub(crate) separator: String,

    // Whether to capitalize the first characters of words.
    pub(crate) capitalize_first: ProbabilityOption,

    // Whether to capitalize whole words.
    pub(crate) capitalize_words: ProbabilityOption,
}

impl Default for PassphraseGenerationOptions {
    fn default() -> Self {
        Self {
            word_list_source: WordListSource::EFFLarge,
            words: 5,
            separator: "-".into(),
            capitalize_first: ProbabilityOption::Always,
            capitalize_words: ProbabilityOption::Never,
        }
    }
}

impl PassphraseGenerationOptions {
    // pub fn generate(&self) -> Result<GeneratedPassPhrase> {
    //     pass_phrase_impl::generate(&self)
    // }

    // Caller needs to pass the word list loader to load any word lists from the resource
    pub fn generate(&self, loader: &impl WordListLoader) -> Result<GeneratedPassPhrase> {
        pass_phrase_impl::generate(&self, loader)
    }
}

mod pass_phrase_impl {
    use crate::{error::Result, password_passphrase_generator::PasswordScore};
    use chbs::{config::BasicConfig, probability, word};
    use log::debug;
    use std::convert::From;

    use super::{
        GeneratedPassPhrase, PassphraseGenerationOptions, ProbabilityOption, WordListSource,
    };

    // Loads the words from a file found under the app specfic resources dir using the passed 'WordListLoader' impl
    fn load_resource_world_list(
        file_name: &str,
        loader: &impl super::WordListLoader,
    ) -> Result<word::WordList> {
        debug!("Resource file name is {}", file_name);
        let content = loader.load_from_resource(file_name)?;
        let words: Vec<String> = content
            .lines()
            .filter(|w| !w.is_empty())
            .filter_map(|w| w.rsplit_terminator(char::is_whitespace).next())
            .map(|w| w.to_owned())
            .collect();

        Ok(word::WordList::new(words))
    }

    pub(crate) fn generate(
        pass_phrase_options: &PassphraseGenerationOptions,
        loader: &impl super::WordListLoader,
    ) -> Result<GeneratedPassPhrase> {
        use WordListSource::*;
        let wl = match pass_phrase_options.word_list_source {
            EFFLarge => word::WordList::builtin_eff_large(),
            EFFShort1 => word::WordList::builtin_eff_short(),
            EFFShort2 => word::WordList::builtin_eff_general_short(),
            ref s @ (Google10000UsaEnglishNoSwearsMedium
            | FrenchDicewareWordlist
            | GermanDicewareWordlist) => load_resource_world_list(s.name(), loader)?,
            Custom(ref wl_file_path) => word::WordList::load_diced(wl_file_path)?,
        };

        let config = BasicConfig {
            words: pass_phrase_options.words,
            word_provider: wl.sampler(),
            separator: pass_phrase_options.separator.clone(),
            capitalize_first: (&pass_phrase_options.capitalize_first).into(),
            capitalize_words: (&pass_phrase_options.capitalize_words).into(),
        };

        let scheme = chbs::scheme::ToScheme::to_scheme(&config);

        let password = scheme.generate();
        let score: PasswordScore = password.as_str().into();
        let gp = GeneratedPassPhrase {
            password,
            score,
            entropy_bits: scheme.entropy().bits(),
        };

        Ok(gp)
    }

    impl From<&ProbabilityOption> for probability::Probability {
        fn from(prob: &ProbabilityOption) -> Self {
            match prob {
                ProbabilityOption::Always => probability::Probability::Always,
                ProbabilityOption::Never => probability::Probability::Never,
                ProbabilityOption::Sometimes(v) => probability::Probability::Sometimes(*v),
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use chbs::{config::BasicConfig, passphrase, probability::Probability, scheme::ToScheme, word};

    use crate::db_service::PasswordScore;

    use super::{PassphraseGenerationOptions, WordListLoader};

    struct WordListLoaderImpl {}

    impl WordListLoader for WordListLoaderImpl {
        fn load_from_resource(&self, _file_name: &str) -> crate::error::Result<String> {
            todo!()
        }
    }

    #[ignore]
    #[test]
    fn verify_with_phrase_generation_options() {
        let mut opt = PassphraseGenerationOptions::default();
        opt.words = 3;
        //opt.capitalize_words = ProbabilityOption::Sometimes(0.5);
        opt.separator = "-".into();

        // println!("deserialized json str is {}", serde_json::to_string_pretty(&opt).unwrap());

        // #[derive(serde::Deserialize, serde::Serialize, Clone)]
        // struct Pref {
        //     pp_options: PassphraseGenerationOptions,
        // }
        // let sd = Pref { pp_options: opt.clone()};
        // println!("deserialized toml str is {}",toml::to_string_pretty(&sd).unwrap());

        let p = opt.generate(&WordListLoaderImpl {}).unwrap();
        //println!("p is {:?}", &p);

        assert_eq!(p.password.split("-").count(), 3, "Expected 3");
    }

    #[ignore]
    #[test]
    fn verify_deserialized_option() {
        let opt_s = r#"{
                        "word_list_source": {
                            "type_name": "EFFLarge"
                        },
                        "words": 4,
                        "separator": "-",
                        "capitalize_first": {
                            "type_name": "Sometimes",
                            "content": 0.5
                        },
                        "capitalize_words": {
                            "type_name": "Never"
                        }
                    }"#;

        let opt = serde_json::from_str::<PassphraseGenerationOptions>(&opt_s).unwrap();
        let p = opt.generate(&WordListLoaderImpl {}).unwrap();
        assert_eq!(p.password.split("-").count(), 4, "Expected 4");
    }

    #[ignore]
    #[test]
    fn verify1() {
        println!("Passphrase: {:?}", passphrase());

        let mut config = BasicConfig::default();
        config.words = 8;
        config.separator = "  -".into();
        config.capitalize_first = Probability::Always;
        //config.capitalize_words = Probability::half();
        let scheme = config.to_scheme();

        println!("Passphrase: {:?}", scheme.generate());
        println!("Entropy: {:?}", scheme.entropy().bits());
    }

    #[ignore]
    #[test]
    fn verify_loading_diced_file() {
        // We can use builder pattern also
        // let mut c_builder = BasicConfigBuilder::<word::WordSampler>::default();
        // c_builder.separator("value").build();

        let path = std::env::current_dir().unwrap();
        println!(" Current dir is {:?}", &path); // test_data/wordlists/wordlist_jp.tx
        let wl_dir_p = path.join("test_data/wordlists/wordlist_jp.txt"); // fr-freelang

        let wl = word::WordList::load_diced(wl_dir_p).unwrap();

        let config = BasicConfig {
            words: 5,
            word_provider: wl.sampler(),
            separator: "-".into(),
            capitalize_first: Probability::half(),
            capitalize_words: Probability::Never,
        };

        let scheme = config.to_scheme();
        let p = scheme.generate();
        let ap: PasswordScore = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        let p = scheme.generate();
        let ap: PasswordScore = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        let p = scheme.generate();
        let ap: PasswordScore = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        assert!(true);
    }
}

// loader is a Fn instead of Trait as was done finally

/*
fn load_resource_world_list_1<F>(file_name: &str, loader: F) -> Result<word::WordList>
    where
        F: Fn(&str) -> Result<String>,
    {
        debug!("Resource file name is {}", file_name);
        let content = loader(file_name)?;
            // CallbackServiceProvider::core_common_callback_service().load_wordlist(file_name)?;

        let words: Vec<String> = content
            .lines()
            .filter(|w| !w.is_empty())
            .filter_map(|w| w.rsplit_terminator(char::is_whitespace).next())
            .map(|w| w.to_owned())
            .collect();

        Ok(word::WordList::new(words))
    }
 */

// Previously the following was used in module callback_service.rs so that
// onekeepass_core we make use of the 'CoreCommonCallbackService' impl
// With the new 'WordListLoader' trait use ( passed as arg to 'generate' fn), this is no more
// required. Keeping it here in case, we can use the conccept if any other need come
/*
use std::
    sync::{Arc, OnceLock}
;

use crate::error::Result;
// This module is used by fns in this crate to use any callback servcices
// to be implemented in the calling UI facing rust crate (e.g tauri, db_service_ffi)


// IMPORTANT
// Need to be called from the UI facing rust layer (tauri or db_service_ffi crate) crate
// onetime when the app is starting

pub fn initialize_with_provider(core_common_callback_service: Arc<dyn CoreCommonCallbackService>) {
    CallbackServiceProvider::init(core_common_callback_service);
}

pub(crate) struct CallbackServiceProvider {
    core_common_callback_service: Arc<dyn CoreCommonCallbackService>,
}

// The UI facing rust implements this trait
pub trait CoreCommonCallbackService: Send + Sync {
    // Called to load a given wordlist file from the app's resource dir
    fn load_wordlist(&self, wordlist_file_name: &str) -> Result<String>;
}

static CALLBACK_PROVIDER: OnceLock<CallbackServiceProvider> = OnceLock::new();

impl CallbackServiceProvider {

    fn init(core_common_callback_service: Arc<dyn CoreCommonCallbackService>) {
        let provider = CallbackServiceProvider {
            core_common_callback_service,
        };

        if CALLBACK_PROVIDER.get().is_none() {
            if CALLBACK_PROVIDER.set(provider).is_err() {
                log::error!(
                        "Global CALLBACK_PROVIDER object is initialized already. This probably happened concurrently."
                    );
            }
        }
    }
    fn shared() -> &'static CallbackServiceProvider {
        // Panics if no global state object was set. ??

        if CALLBACK_PROVIDER.get().is_none() {
            log::error!("CALLBACK_PROVIDER is not yet. This will result in pani!!! - Needs fixing in dev time itself")
        }
        CALLBACK_PROVIDER.get().unwrap()
    }

    pub(crate) fn core_common_callback_service() -> &'static dyn CoreCommonCallbackService {
        Self::shared().core_common_callback_service.as_ref()
    }
}

*/

/*

use crate::{
        callback_service::{CallbackServiceProvider, CoreCommonCallbackService}, error::Result,
        password_passphrase_generator::PasswordScore,
    };

fn load_resource_world_list(file_name: &str) -> Result<word::WordList> {
        debug!("Resource file name is {}", file_name);
        let content =
            CallbackServiceProvider::core_common_callback_service().load_wordlist(file_name)?;

        let words: Vec<String> = content
            .lines()
            .filter(|w| !w.is_empty())
            .filter_map(|w| w.rsplit_terminator(char::is_whitespace).next())
            .map(|w| w.to_owned())
            .collect();

        Ok(word::WordList::new(words))
    }

pub(crate) fn generate(
        pass_phrase_options: &PassphraseGenerationOptions,
    ) -> Result<GeneratedPassPhrase> {
        use WordListSource::*;
        let wl = match pass_phrase_options.word_list_source {
            EFFLarge => word::WordList::builtin_eff_large(),
            EFFShort1 => word::WordList::builtin_eff_short(),
            EFFShort2 => word::WordList::builtin_eff_general_short(),
            ref s @ (Google10000UsaEnglishNoSwearsMedium
            | FrenchDicewareWordlist
            | GermanDicewareWordlist) => load_resource_world_list(s.name())?,
            Custom(ref wl_file_path) => word::WordList::load_diced(wl_file_path)?,
        };

        let config = BasicConfig {
            words: pass_phrase_options.words,
            word_provider: wl.sampler(),
            separator: pass_phrase_options.separator.clone(),
            capitalize_first: (&pass_phrase_options.capitalize_first).into(),
            capitalize_words: (&pass_phrase_options.capitalize_words).into(),
        };

        let scheme = chbs::scheme::ToScheme::to_scheme(&config);

        let password = scheme.generate();
        let score: PasswordScore = password.as_str().into();
        let gp = GeneratedPassPhrase {
            password,
            score,
            entropy_bits: scheme.entropy().bits(),
        };

        Ok(gp)
    }


*/
