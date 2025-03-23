use passwords;

use crate::error::Result;
use serde::{Deserialize, Serialize};

// This one has the same structure as passwords::PasswordGenerator but implements Deserialize, Serialize so that
// we can use in json marshalling to UI layer and back
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct PasswordGenerationOptions {
    /// The length of the generated passwords.
    ///
    /// Default: `8`
    pub length: usize,
    /// Passwords are allowed to, or must if the strict is true, contain a number or numbers.
    ///
    /// Default: `true`
    pub numbers: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a lowercase letter or lowercase letters.
    ///
    /// Default: `true`
    pub lowercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain an uppercase letter or uppercase letters.
    ///
    /// Default: `false`
    pub uppercase_letters: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a symbol or symbols.
    ///
    /// Default: `false`
    pub symbols: bool,
    /// Passwords are allowed to, or must if the strict is true, contain a space or spaces.
    ///
    /// Default: `false`
    pub spaces: bool,
    /// Whether to exclude similar characters, ``iI1loO0"'`|``.
    ///
    /// Default: `false`
    pub exclude_similar_characters: bool,
    /// Whether the password rules are strict.
    ///
    /// Default: `false`
    pub strict: bool,
}

impl PasswordGenerationOptions {
    pub const fn new() -> PasswordGenerationOptions {
        PasswordGenerationOptions {
            length: 8,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: false,
            symbols: false,
            spaces: false,
            exclude_similar_characters: false,
            strict: false,
        }
    }

    pub fn generate(&self) -> Result<String> {
        // Delegate to the actual PasswordGenerator
        let pg = passwords::PasswordGenerator {
            length: self.length,
            numbers: self.numbers,
            lowercase_letters: self.lowercase_letters,
            uppercase_letters: self.uppercase_letters,
            symbols: self.symbols,
            spaces: self.spaces,
            exclude_similar_characters: self.exclude_similar_characters,
            strict: self.strict,
        };
        // extern crate passwords returns error as static &str and this is
        // converted to 'crate::onekeepass_core::error::Error implementing From trait
        Ok(pg.generate_one()?)
    }

    pub fn analyzed_password(&self) -> Result<AnalyzedPassword> {
        self.generate().map(|s| analyze_password(&s))
    }
}

impl Default for PasswordGenerationOptions {
    #[inline]
    fn default() -> PasswordGenerationOptions {
        PasswordGenerationOptions::new()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
/// The struct of an analysis.
pub struct AnalyzedPassword {
    pub password: String,
    pub analyzed_password: String,
    pub length: usize,
    pub spaces_count: usize,
    pub numbers_count: usize,
    pub lowercase_letters_count: usize,
    pub uppercase_letters_count: usize,
    pub symbols_count: usize,
    pub other_characters_count: usize,
    pub consecutive_count: usize,
    pub non_consecutive_count: usize,
    pub progressive_count: usize,
    pub is_common: bool,
    pub score: PasswordScore,
}

// #[derive(Deserialize, Serialize,Debug,Clone)]
// pub struct ScoreDetail {
//     raw_value:f64, score_text:String
// }

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(tag = "name")]
#[non_exhaustive]
pub enum PasswordScore {
    VeryDangerous { raw_value: f64, score_text: String },
    Dangerous { raw_value: f64, score_text: String },
    VeryWeak { raw_value: f64, score_text: String },
    Weak { raw_value: f64, score_text: String },
    Good { raw_value: f64, score_text: String },
    Strong { raw_value: f64, score_text: String },
    VeryStrong { raw_value: f64, score_text: String },
    Invulnerable { raw_value: f64, score_text: String },
}

impl From<&str> for PasswordScore {
    fn from(password: &str) -> Self {
        analyze_password(password).score
    }
}

impl From<&String> for PasswordScore {
    fn from(password: &String) -> Self {
        analyze_password(password).score
    }
}

impl From<f64> for PasswordScore {
    fn from(raw_value: f64) -> Self {
        if raw_value >= 0.0 && raw_value <= 20.0 {
            PasswordScore::VeryDangerous {
                raw_value,
                score_text: "Very Dangerous".into(),
            }
        } else if raw_value > 20.0 && raw_value <= 40.0 {
            PasswordScore::Dangerous {
                raw_value,
                score_text: "Dangerous".into(),
            }
        } else if raw_value > 40.0 && raw_value <= 60.0 {
            PasswordScore::VeryWeak {
                raw_value,
                score_text: "Very Weak".into(),
            }
        } else if raw_value > 60.0 && raw_value <= 80.0 {
            PasswordScore::Weak {
                raw_value,
                score_text: "Weak".into(),
            }
        } else if raw_value > 80.0 && raw_value <= 90.0 {
            PasswordScore::Good {
                raw_value,
                score_text: "Good".into(),
            }
        } else if raw_value > 90.0 && raw_value <= 95.0 {
            PasswordScore::Strong {
                raw_value,
                score_text: "Strong".into(),
            }
        } else if raw_value > 95.0 && raw_value <= 99.0 {
            PasswordScore::VeryStrong {
                raw_value,
                score_text: "Very Strong".into(),
            }
        } else {
            // raw_score <= 100.0 && raw_score > 99.0
            PasswordScore::Invulnerable {
                raw_value,
                score_text: "Invulnerable".into(),
            }
        }
    }
}

#[allow(dead_code)]
fn analyze_password(password: &str) -> AnalyzedPassword {
    let analyzed = passwords::analyzer::analyze(password);

    // A password whose score is,

    // 0 ~ 20 is very dangerous (may be cracked within few seconds)
    // 20 ~ 40 is dangerous
    // 40 ~ 60 is very weak
    // 60 ~ 80 is weak
    // 80 ~ 90 is good
    // 90 ~ 95 is strong
    // 95 ~ 99 is very strong
    // 99 ~ 100 is invulnerable

    let score = passwords::scorer::score(&analyzed).into();

    AnalyzedPassword {
        password: password.into(),
        analyzed_password: analyzed.password().into(),
        length: analyzed.length(),
        spaces_count: analyzed.spaces_count(),

        numbers_count: analyzed.numbers_count(),
        lowercase_letters_count: analyzed.lowercase_letters_count(),
        uppercase_letters_count: analyzed.uppercase_letters_count(),
        symbols_count: analyzed.symbols_count(),
        other_characters_count: analyzed.other_characters_count(),
        consecutive_count: analyzed.consecutive_count(),
        non_consecutive_count: analyzed.non_consecutive_count(),
        progressive_count: analyzed.progressive_count(),
        is_common: analyzed.is_common(),
        score,
    }
}

// pub fn score_password(password: &str) -> PasswordScore {
//     analyze_password(password).score
// }

#[cfg(test)]
mod tests {

    use crate::password_passphrase_generator::password_generator::*;

    #[test]
    fn verify_password_1() {
        let mut po = PasswordGenerationOptions::new();
        po.symbols = true;
        po.length = 21;
        let pwd = po.generate().unwrap();
        println!("P is {}", pwd);
    }

    #[test]
    fn verify_analyze() {
        let mut po = PasswordGenerationOptions::new();
        po.spaces = true;
        let pwd = po.generate().unwrap();
        let result = analyze_password(&pwd);
        println!("result is {:?}", result);
        assert_eq!(result.lowercase_letters_count > 1, true);

        // let s = 4.5f64;
        // let r = s <= 4.5 && s >= 3.0;
        // println!("result {}", r);
    }

    #[test]
    fn verify_readable_password() {
        //See
        // Before the analyzer analyzes a password, it filters the password in order
        // to remove its control characters (control characters like BS, LF, CR, etc). And after analyzing,
        // the analyzer will return the filtered password.
        let pwd = "ZYX[$BCkQB中文}%A_3456]  H(\rg";
        let result = analyze_password(&pwd);
        println!("result is {:?}", result);
        assert_eq!("ZYX[$BCkQB中文}%A_3456]  H(g", result.analyzed_password); // "\r" was filtered
    }
}
