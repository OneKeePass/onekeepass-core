use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::Result;

use super::PasswordScore;

#[derive(Deserialize, Serialize,Debug)]
pub struct GeneratedPassPhrase {
    password: String,
    score: PasswordScore,
    entropy_bits: f64,
}

#[derive(Deserialize, Serialize, Clone,Debug)]
#[serde(tag = "name", content = "source")]
pub enum WordListSource {
    EFFLarge,
    EFFShort1,
    EFFShort2,
    Custom(String),
}

// Similar to chbs::probability::Probability with serilaization support
#[derive(Deserialize, Serialize, Clone,Debug)]
#[serde(tag = "type_name", content = "value")]
pub enum ProbabilityOption {
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

#[derive(Deserialize, Serialize, Clone,Debug)]
pub struct PassphraseGenerationOptions {
    pub(crate) word_list_source:WordListSource,

    // No of words in the phrase
    pub(crate) words: usize,

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
            word_list_source:WordListSource::EFFLarge,
            words: 5,
            separator: " ".into(),
            capitalize_first: ProbabilityOption::Always,
            capitalize_words: ProbabilityOption::Never,
        }
    }
}

impl PassphraseGenerationOptions {
    pub fn generate(&self) -> Result<GeneratedPassPhrase> {
        pass_phrase_impl::generate(&self)
    }
}

mod pass_phrase_impl {
    use crate::{error::Result, password_passphrase_generator::PasswordScore};
    use chbs::{config::BasicConfig, probability, word};
    use std::convert::From;

    use super::{GeneratedPassPhrase, PassphraseGenerationOptions, ProbabilityOption, WordListSource};

    pub(crate) fn generate(
        pass_phrase_options: &PassphraseGenerationOptions,
    ) -> Result<GeneratedPassPhrase> {
        
        let wl = match pass_phrase_options.word_list_source {
            WordListSource::EFFLarge => word::WordList::builtin_eff_large(),
            WordListSource::EFFShort1 => word::WordList::builtin_eff_short(),
            WordListSource::EFFShort2 => word::WordList::builtin_eff_general_short(),
            WordListSource::Custom(ref wl_file_path) => {
                word::WordList::load_diced(wl_file_path)?
            }
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
    use chbs::{
        config::BasicConfig, passphrase, probability::Probability, scheme::ToScheme, word
    };

    use crate::{db_service::PasswordScore, password_passphrase_generator::passphrase_generator::ProbabilityOption};

    use super::PassphraseGenerationOptions;

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
        
        let p = opt.generate().unwrap();
        //println!("p is {:?}", &p);

        assert_eq!(p.password.split("-").count(),3, "Expected 3");
    }

    #[test]
    fn verify_deserialized_option() {
        let opt_s = r#"{
                        "word_list_source": {
                            "name": "EFFLarge"
                        },
                        "words": 4,
                        "separator": "-",
                        "capitalize_first": {
                            "type_name": "Sometimes",
                            "value": 0.5
                        },
                        "capitalize_words": {
                            "type_name": "Never"
                        }
                    }"#;

        let opt = serde_json::from_str::<PassphraseGenerationOptions>(&opt_s).unwrap();
        let p = opt.generate().unwrap();
        assert_eq!(p.password.split("-").count(),4, "Expected 4");
    }

    #[test]
    fn verify1() {
        println!("Passphrase: {:?}", passphrase());

        let mut config = BasicConfig::default();
        config.words = 8;
        config.separator = "  -".into();
        config.capitalize_first = Probability::Always;
        //config.capitalize_words = Probability::half();
        let  scheme = config.to_scheme();

        println!("Passphrase: {:?}", scheme.generate());
        println!("Entropy: {:?}", scheme.entropy().bits());
    }

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
        let ap:PasswordScore = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        let p = scheme.generate();
        let ap:PasswordScore  = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        let p = scheme.generate();
        let ap:PasswordScore  = (&p).into();
        println!("Passphrase: {:?} with score {:?}", &p, ap);
        println!("Entropy: {:?}", scheme.entropy().bits());

        assert!(true);
    }
}
