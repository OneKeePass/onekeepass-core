use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    constants::OTP_URL_PREFIX,
    crypto::{hmac_sha1_from_slice, hmac_sha256_from_slice, hmac_sha512_from_slice},
    error::{Error, Result},
    util::strip_spaces,
};

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentOtpTokenData {
    pub(crate) token: String,
    pub(crate) ttl: u64,
    pub(crate) period: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OtpSettings {
    pub secret_or_url: String,
    pub period: Option<u64>,
    pub digits: Option<usize>,
    pub hash_algorithm: Option<OtpAlgorithm>,
}

impl OtpSettings {
    pub fn otp_url(&self) -> Result<String> {
        let od = OtpData::from_otp_settings(self)?;
        Ok(od.get_url())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl std::default::Default for OtpAlgorithm {
    fn default() -> Self {
        OtpAlgorithm::SHA1
    }
}

impl fmt::Display for OtpAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpAlgorithm::SHA1 => f.write_str("SHA1"),
            OtpAlgorithm::SHA256 => f.write_str("SHA256"),
            OtpAlgorithm::SHA512 => f.write_str("SHA512"),
        }
    }
}

impl OtpAlgorithm {
    fn sign(&self, decoded_secret: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            OtpAlgorithm::SHA1 => hmac_sha1_from_slice(decoded_secret, data),
            OtpAlgorithm::SHA256 => hmac_sha256_from_slice(decoded_secret, data),
            OtpAlgorithm::SHA512 => hmac_sha512_from_slice(decoded_secret, data),
            // _ => Err(Error::DataError("()")),
        }
    }
}

macro_rules! verify_period {
    ($period:expr) => {
        if $period < 1 || $period > 60 {
            return Err(Error::UnexpectedError(format!(
                "Period should be in the range 1 - 60"
            )));
        }
    };
}

macro_rules! verify_digits {
    ($digits:expr) => {
        if $digits < 6 || $digits > 10 {
            return Err(Error::UnexpectedError(format!(
                "Digits should be in the range 6 - 10"
            )));
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OtpData {
    // non-encoded value
    // Any base32 encoded incoming value needs to be decoded
    pub(crate) decoded_secret: Vec<u8>,
    // Duration in seconds of a period or a step.
    // The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 30 seconds
    pub(crate) period: u64,
    // The number of digits composing the auth code.
    // Per [rfc-4226](https://tools.ietf.org/html/rfc4226#section-5.3), this may be between 6 and 8 digits
    pub(crate) digits: usize,
    // Number of steps allowed as network delay. 1 would mean one step before current step and one step after are valids.
    // The recommended value per [rfc-6238](https://tools.ietf.org/html/rfc6238#section-5.2) is 1.
    pub(crate) skew: u8,
    // SHA-1 is the most widespread algorithm used
    pub(crate) algorithm: OtpAlgorithm,
    pub(crate) issuer: Option<String>,
    pub(crate) account_name: Option<String>,
}

fn system_time() -> Result<u64> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(t)
}

impl OtpData {
    #[allow(dead_code)]
    pub fn new(
        algorithm: OtpAlgorithm,
        // expects a base32 encoded string as secret key and will be decoded
        encoded_secret: &str,
        digits: usize,
        period: u64,
        issuer: Option<String>,
        account_name: Option<String>,
    ) -> Result<OtpData> {
        Ok(OtpData {
            decoded_secret: BASE32_NOPAD.decode(encoded_secret.as_bytes())?,
            period,
            digits,
            skew: 1,
            algorithm,
            issuer,
            account_name,
        })
    }

    pub fn from_otp_settings(otp_settings: &OtpSettings) -> Result<OtpData> {
        if otp_settings.secret_or_url.starts_with(OTP_URL_PREFIX) {
            OtpData::from_url(&otp_settings.secret_or_url)
        } else {
            let mut otp_data = OtpData::from_key(&otp_settings.secret_or_url)?;
            if let Some(period) = otp_settings.period {
                verify_period!(period);
                otp_data.period = period;
            }
            if let Some(digits) = otp_settings.digits {
                otp_data.digits = digits;
                verify_digits!(digits);
            }

            if let Some(alg) = otp_settings.hash_algorithm {
                otp_data.algorithm = alg;
            }

            Ok(otp_data)
        }
    }

    pub fn from_key(encoded_secret: &str) -> Result<OtpData> {
        let space_removed = strip_spaces(encoded_secret).to_uppercase();
        if space_removed.is_empty() {
            return Err(Error::UnexpectedError(format!(
                "Decoding failed as secret code entered is empty. Requires US-ASCII uppercase letters and digits"))) ;
        }

        Ok(OtpData {
            decoded_secret: BASE32_NOPAD
                .decode(space_removed.as_bytes())
                .map_err(|e| {
                    Error::OtpKeyDecodeError(format!(
                        "Decoding '{}' failed with error {}. Requires US-ASCII uppercase letters and digits",
                        space_removed, e
                    ))
                })?,
            period: 30,
            digits: 6,
            skew: 1,
            algorithm: OtpAlgorithm::SHA1,
            issuer: None,
            account_name: None,
        })
    }

    pub fn from_url(otp_url: &str) -> Result<OtpData> {
        let mut algorithm = OtpAlgorithm::SHA1;
        let mut digits = 6;
        let mut period = 30;
        let mut secret = Vec::new();
        let mut issuer: Option<String> = None;
        #[allow(unused_assignments)]
        let mut account_name: Option<String> = None;

        let parsed_url = Url::parse(otp_url)?;
        if parsed_url.scheme() != "otpauth" {
            return Err(Error::DataError("Url is not otp url"));
        }

        match parsed_url.host_str() {
            Some(x) if x == "totp" => {}
            Some(x) if x == "hotp" => {
                return Err(Error::OtpUrlParseError("HOTP is not supported".into()));
            }
            _ => {
                return Err(Error::OtpUrlParseError("Url is not otp url".into()));
            }
        }

        // Gets the path after 'otpauth://totp/'
        let path = parsed_url.path().trim_start_matches('/');
        let path = urlencoding::decode(path)?.to_string();

        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            account_name = Some(parts.1.to_owned());
        } else {
            account_name = Some(path);
        }

        for (key, value) in parsed_url.query_pairs() {
            match key.as_ref() {
                "algorithm" => {
                    println!("Algorithm is {}", value.as_ref());
                    algorithm = match value.as_ref() {
                        "SHA1" => OtpAlgorithm::SHA1,
                        "SHA256" => OtpAlgorithm::SHA256,
                        "SHA512" => OtpAlgorithm::SHA512,
                        _ => {
                            return Err(Error::OtpUrlParseError(format!(
                                "Invalid algorithm value {}",
                                value
                            )));
                        }
                    }
                }
                "digits" => {
                    digits = value.parse::<usize>().map_err(|_| {
                        Error::OtpUrlParseError(format!(
                            "Invalid digits value {} passed in the url",
                            value
                        ))
                    })?;
                    verify_digits!(digits);
                }
                "period" => {
                    period = value.parse::<u64>().map_err(|_| {
                        Error::OtpUrlParseError(format!(
                            "Invalid period value {} passed in the url",
                            value
                        ))
                    })?;
                    verify_period!(period);
                }
                "secret" => {
                    // log::debug!("Secret is {}", value.as_ref());

                    // Ensure that we have secret in uppercase
                    // Otherwise BASE32_NOPAD.decode will fail
                    let s = value.to_uppercase();

                    // log::debug!("Secret after uppercase call is {}", &s);

                    secret = BASE32_NOPAD.decode(s.as_bytes()).map_err(|e| {
                        Error::OtpUrlParseError(format!(
                            "Invalid secret code. Decoding of '{}' in the url failed with error {}",
                            s, e
                        ))
                    })?;
                }

                "issuer" => {
                    let param_issuer: String = value.into();

                    if issuer.is_some() && param_issuer.as_str() != issuer.as_ref().unwrap() {
                        return Err(Error::OtpUrlParseError(format!("Issuer mismatch")));
                    }
                    issuer = Some(param_issuer);
                }

                _ => {}
            }
        }

        if secret.is_empty() {
            return Err(Error::OtpUrlParseError("Key value cannot be empty".into()));
        }

        Ok(OtpData {
            algorithm,
            decoded_secret: secret,
            period,
            digits,
            skew: 1,
            issuer,
            account_name,
        })
    }

    // Does a hmac sign of the given timestamp
    pub fn sign(&self, time: u64) -> Result<Vec<u8>> {
        self.algorithm.sign(
            self.decoded_secret.as_ref(),
            (time / self.period).to_be_bytes().as_ref(),
        )
    }

    // Will generate a token for the provided timestamp in seconds
    pub fn generate(&self, time: u64) -> Result<String> {
        let signed_bytes: &[u8] = &self.sign(time)?;

        // Make sure that we have last element call succeed as we do unwrap call later
        // if result.last().is_none() {
        //     return Err(Error::UnexpectedError(
        //         "Token generation failed to get last byte from signed bytes".into(),
        //     ));
        // }
        // let offset = (result.last().unwrap() & 15) as usize;

        let Some(last_byte) = signed_bytes.last() else {
            return Err(Error::UnexpectedError(
                "Token generation failed to get last byte from the signed bytes".into(),
            ));
        };

        let offset = (last_byte & 15) as usize;

        // log::debug!("offset calculated is {} for result with size {} and will look bytes from {} to {} in result bytes",offset,result.len(), offset, offset+4);

        // Extract the 4 bytes
        let offset_result: [u8; 4] = signed_bytes[offset..offset + 4].try_into().map_err(|e| {
            Error::UnexpectedError(format!(
                "Token generation failed during offeset calculation with error {}",
                e
            ))
        })?;

        //#[allow(unused_mut)]
        let result = u32::from_be_bytes(offset_result) & 0x7fff_ffff;

        //IMPORTANT: we need to use 10_u64 instead of using 10_u32 as it will result in num overflow error while calculating 10^10
        let ten_pow: Option<u64> = 10_u64.checked_pow(self.digits as u32);
        //log::debug!("ten_pow calculated is {}",&ten_pow);

        let Some(ten_pow) = ten_pow else {
            return Err(Error::UnexpectedError(
                "10th Power calculation number overflows".into(),
            ));
        };

        let final_num = (result as u64)
            .checked_rem(ten_pow)
            .ok_or_else(|| Error::UnexpectedError("Invalid remainder calculation".into()))?;

        //let final_num = result as u64 % ten_pow;
        //log::debug!("final_num calculated is {}",&final_num);

        let s = format!("{1:00$}", self.digits, final_num);

        Ok(s)
    }

    // Generate a token from the current system time
    pub fn generate_current(&self) -> Result<String> {
        let t = system_time()?;
        self.generate(t)
    }

    // Generate a token from the current system time
    pub fn current_otp_token_data(&self) -> Result<CurrentOtpTokenData> {
        Ok(CurrentOtpTokenData {
            token: self.generate_current()?,
            ttl: self.ttl()?,
            period: self.period,
        })
    }

    // Returns the timestamp of the first second for the next period
    // given the provided timestamp in seconds
    fn _next_period(&self, time: u64) -> u64 {
        let period = time / self.period;
        (period + 1) * self.period
    }

    // Returns the timestamp of the first second of the next step
    // According to system time
    fn _next_step_current(&self) -> Result<u64> {
        let t = system_time()?;
        Ok(self._next_period(t))
    }

    // Give the ttl (in seconds) of the current token
    pub fn ttl(&self) -> Result<u64> {
        let t = system_time()?;
        Ok(self.period - (t % self.period))
    }

    // Will return the base32 representation of the secret,
    // which might be useful when users want to see
    pub fn get_secret_base32(&self) -> String {
        BASE32_NOPAD.encode(self.decoded_secret.as_ref())
    }

    pub fn get_url(&self) -> String {
        #[allow(unused_mut)]
        let mut host = "totp";
        let account_name = self.account_name.as_ref().map_or_else(|| "None", |v| v);
        let account_name = urlencoding::encode(account_name).to_string();
        let mut params = vec![format!("secret={}", self.get_secret_base32())];
        if self.digits != 6 {
            params.push(format!("digits={}", self.digits));
        }
        if self.algorithm != OtpAlgorithm::SHA1 {
            params.push(format!("algorithm={}", self.algorithm));
        }
        let label = if let Some(issuer) = &self.issuer {
            let issuer = urlencoding::encode(issuer);
            params.push(format!("issuer={}", issuer));
            format!("{}:{}", issuer, account_name)
        } else {
            account_name
        };
        if self.period != 30 {
            params.push(format!("period={}", self.period));
        }

        format!("otpauth://{}/{}?{}", host, label, params.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::SystemTime};

    use data_encoding::BASE32_NOPAD;

    use super::{OtpData, OtpSettings};
    use crate::db_content::otp::OtpAlgorithm;
    use crate::util::init_test_logging;

    struct V1 {
        ascii_key: String,
        encoded_key: String,
        time: u64,
        token: String,
    }

    impl V1 {
        fn new(ascii_key: &str, time: u64, token: &str) -> Self {
            Self {
                ascii_key: ascii_key.to_string(),
                encoded_key: BASE32_NOPAD.encode(ascii_key.as_bytes()),
                time,
                token: token.to_string(),
            }
        }
    }

    // Refer
    // https://datatracker.ietf.org/doc/html/rfc6238#appendix-B (Appendix B.  Test Vectors)
    // https://github.com/pyauth/pyotp/blob/develop/test.py

    // encoded value GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    static TEST_KEY_SHA1: &str = "12345678901234567890";

    // encoded value GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA
    static TEST_KEY_SHA256: &str = "12345678901234567890123456789012";

    // encoded value GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA
    static TEST_KEY_SHA512: &str =
        "1234567890123456789012345678901234567890123456789012345678901234";

    fn test_rfc_values() -> HashMap<String, Vec<V1>> {
        let m: HashMap<String, Vec<V1>> = HashMap::from([
            (
                "SHA1".into(),
                vec![
                    V1::new(TEST_KEY_SHA1, 59, "94287082"),
                    V1::new(TEST_KEY_SHA1, 1111111109, "07081804"),
                    V1::new(TEST_KEY_SHA1, 1111111111, "14050471"),
                    V1::new(TEST_KEY_SHA1, 2000000000, "69279037"),
                    V1::new(TEST_KEY_SHA1, 20000000000, "65353130"),
                ],
            ),
            (
                "SHA256".into(),
                vec![
                    V1::new(TEST_KEY_SHA256, 59, "46119246"),
                    V1::new(TEST_KEY_SHA256, 1111111109, "68084774"),
                    V1::new(TEST_KEY_SHA256, 1111111111, "67062674"),
                    V1::new(TEST_KEY_SHA256, 1234567890, "91819424"),
                    V1::new(TEST_KEY_SHA256, 2000000000, "90698825"),
                    V1::new(TEST_KEY_SHA256, 20000000000, "77737706"),
                ],
            ),
            (
                "SHA512".into(),
                vec![
                    V1::new(TEST_KEY_SHA512, 59, "90693936"),
                    V1::new(TEST_KEY_SHA512, 1111111109, "25091201"),
                    V1::new(TEST_KEY_SHA512, 1111111111, "99943326"),
                    V1::new(TEST_KEY_SHA512, 1234567890, "93441116"),
                    V1::new(TEST_KEY_SHA512, 2000000000, "38618901"),
                    V1::new(TEST_KEY_SHA512, 20000000000, "47863826"),
                ],
            ),
        ]);

        m
    }

    #[test]
    fn verify_totp_sha1_with_test_vectors() {
        init_test_logging();
        let data = test_rfc_values();

        for v in data.get("SHA1").unwrap().iter().into_iter() {
            let od = OtpData::new(OtpAlgorithm::SHA1, &v.encoded_key, 8, 30, None, None).unwrap();
            assert_eq!(
                od.generate(v.time).unwrap(),
                v.token,
                "Failed test case time {}, ascii_key {} ",
                v.time,
                v.ascii_key
            );
        }
    }

    #[test]
    fn verify_totp_sha256_with_test_vectors() {
        let data = test_rfc_values();

        for v in data.get("SHA256").unwrap().iter().into_iter() {
            let od = OtpData::new(OtpAlgorithm::SHA256, &v.encoded_key, 8, 30, None, None).unwrap();
            assert_eq!(
                od.generate(v.time).unwrap(),
                v.token,
                "Failed test case time {}, ascii_key {} ",
                v.time,
                v.ascii_key
            );
        }
    }

    #[test]
    fn verify_totp_sha512_with_test_vectors() {
        let data = test_rfc_values();

        for v in data.get("SHA512").unwrap().iter().into_iter() {
            let od = OtpData::new(OtpAlgorithm::SHA512, &v.encoded_key, 8, 30, None, None).unwrap();
            assert_eq!(
                od.generate(v.time).unwrap(),
                v.token,
                "Failed test case time {}, ascii_key {} ",
                v.time,
                v.ascii_key
            );
        }
    }

    #[test]
    fn verify_using_settings() {
        //from_otp_settings
        let mut settings = OtpSettings {
            period: Some(10),
            digits: Some(6),
            secret_or_url: "base 32se cret 3232".into(),
            hash_algorithm: Some(OtpAlgorithm::SHA1),
        };

        let otp = OtpData::from_otp_settings(&settings);
        assert!(otp.is_ok());

        settings.secret_or_url = "BASE32SECRET3232".into();
        let otp = OtpData::from_otp_settings(&settings);
        assert!(otp.is_ok());

        // digit 1 is not valid
        settings.secret_or_url = "BASE32SECRET3231".into();
        let otp = OtpData::from_otp_settings(&settings);
        assert!(otp.is_err());

        // Not sufficient length
        settings.secret_or_url = "BASE32SECRET".into();
        let otp = OtpData::from_otp_settings(&settings);
        assert!(otp.is_err());

        // Not correct length - multiple of 8?
        settings.secret_or_url = "BASE32SECRET32323232".into();
        let otp = OtpData::from_otp_settings(&settings);
        assert!(otp.is_err());

        println!("Error is {:?}", otp);
    }

    #[test]
    fn from_url_err() {
        // HOTP is not supported
        let r = OtpData::from_url("otpauth://hotp/123");
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());

        // Shared Key cannot be empty
        let r = OtpData::from_url("otpauth://totp/GitHub:test");
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());

        // secret decoding error
        let r = OtpData::from_url(
            "otpauth://totp/GitHub:test:?secret=ABC&digits=8&period=60&algorithm=SHA256",
        );

        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());

        // Issuer mismatch error
        let r = OtpData::from_url("otpauth://totp/Github:john.doe%40github.com?issuer=GitHub&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1");
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());
    }

    #[test]
    fn verify_url_max_digits_period() {
        init_test_logging();
        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=10&period=60&algorithm=SHA1";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_ok());
        let n = r.unwrap().generate_current();
        assert!(n.is_ok());

        println!("Generated Token is {}", n.unwrap());
    }

    #[test]
    fn verify_url_min_digits_period() {
        init_test_logging();
        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=6&period=1&algorithm=SHA1";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_ok());
        let n = r.unwrap().generate_current();

        assert!(n.is_ok());
        println!("Generated Token is {}", n.unwrap());
    }

    #[test]
    fn verify_url_with_lowercase_secret() {
        init_test_logging();
        // secret is in lowercase
        let url = "otpauth://totp/Google%3Ajeyms2002%40gmail.com?secret=i26ce7wthhpa2oqvoo6jb4mmy2uqxgb3&issuer=Google";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_ok());

        let otp = r.unwrap();
        // println!("Parsed otp data {:?} and url {}",&otp, &otp.get_url());

        let n = otp.generate_current();

        assert!(n.is_ok());
        println!("Generated Token is {}", n.unwrap());

        // Same url with uppercase
        let url = "otpauth://totp/Google:jeyms2002@gmail.com?secret=I26CE7WTHHPA2OQVOO6JB4MMY2UQXGB3&issuer=Google";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_ok());
    }

    #[test]
    fn verify_url_digits_range_error() {
        init_test_logging();
        // Accepted range 6 - 10
        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=11&period=60";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());

        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=5&period=60";
        let r = OtpData::from_url(url);

        assert!(r.is_err());
    }

    #[test]
    fn verify_url_period_range_error() {
        init_test_logging();

        // Accepted period 1 - 60

        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=10&period=65";
        let r = OtpData::from_url(url);
        if r.is_err() {
            println!("Error is {:?}", r);
        }
        assert!(r.is_err());

        let url = "otpauth://totp/None?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&digits=10&period=0";
        let r = OtpData::from_url(url);

        assert!(r.is_err());
    }

    #[test]
    fn url_for_secret_matches_sha1_without_issuer() {
        // "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ" is the base32 encoded value
        // derived from the bytes of "TestSecretSuperSecret"
        let totp = OtpData::new(
            OtpAlgorithm::SHA1,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            30,
            None,
            Some("john.doe@github.com".to_string()),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(
            url.as_str(),
            "otpauth://totp/john.doe%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    fn url_for_secret_matches_sha1() {
        let totp = OtpData::new(
            OtpAlgorithm::SHA1,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            30,
            Some("Github".to_string()),
            Some("john.doe@github.com".to_string()),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:john.doe%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha256() {
        let totp = OtpData::new(
            OtpAlgorithm::SHA256,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            30,
            Some("Github".to_string()),
            Some("john.doe@github.com".to_string()),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:john.doe%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github");
    }

    #[test]
    fn url_for_secret_matches_sha512() {
        let totp = OtpData::new(
            OtpAlgorithm::SHA512,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            30,
            Some("Github".to_string()),
            Some("john.doe@github.com".to_string()),
        )
        .unwrap();
        let url = totp.get_url();
        assert_eq!(url.as_str(), "otpauth://totp/Github:john.doe%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA512&issuer=Github");
    }

    #[test]
    fn from_url_to_url() {
        let totp = OtpData::from_url("otpauth://totp/Github:john.doe%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1").unwrap();
        let totp_bis = OtpData::new(
            OtpAlgorithm::SHA1,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            30,
            Some("Github".to_string()),
            Some("john.doe@github.com".to_string()),
        )
        .unwrap();
        assert_eq!(totp.get_url(), totp_bis.get_url());
    }

    #[test]
    fn generate_token_current() {
        let totp = OtpData::new(
            OtpAlgorithm::SHA1,
            "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ",
            6,
            1,
            None,
            None,
        )
        .unwrap();
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            totp.generate(time).unwrap().as_str(),
            totp.generate_current().unwrap()
        );
    }

    ///////////
    #[test]
    fn verify1_totp_59_sec() {
        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890".as_bytes());
        // Encoded key is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        println!("Encoded key is {}", key);
        let dk = data_encoding::BASE32_NOPAD.decode(key.as_bytes()).unwrap();
        println!("Decoded key is {:?}", String::from_utf8(dk));
        let mut od = OtpData::from_key(key.as_str()).unwrap();
        od.digits = 8;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(59),
            od.ttl()
        );

        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890123456789012".as_bytes());
        println!("Encoded key is {}", key);
        let mut od = OtpData::from_key(key.as_str()).unwrap();
        od.digits = 8;
        od.algorithm = OtpAlgorithm::SHA256;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(59),
            od.ttl()
        );

        let key = data_encoding::BASE32_NOPAD
            .encode("1234567890123456789012345678901234567890123456789012345678901234".as_bytes());
        let mut od = OtpData::from_key(key.as_str()).unwrap();
        od.digits = 8;
        od.algorithm = OtpAlgorithm::SHA512;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(59),
            od.ttl()
        );
    }

    #[test]
    fn verify_totp_1111111109_sec() {
        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890".as_bytes());
        let mut od = OtpData::from_key(key.as_str()).unwrap();
        od.digits = 8;
        od.algorithm = OtpAlgorithm::SHA1;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(1111111109),
            od.ttl()
        );

        // Encoded key is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        // od.get_secret_base32() is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        println!("Key is {}", od.get_secret_base32());
    }

    #[test]
    fn verify_otp1() {
        let od = OtpData::from_key("BASE32SECRET3232").unwrap();
        println!("Od is {:?}", od);

        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate_current(),
            od.ttl()
        );
    }
}

/*
 pub fn from_key_digits(encoded_secret: &str, digits: usize) -> Result<OtpData> {
        Ok(OtpData {
            decoded_secret: BASE32_NOPAD.decode(encoded_secret.as_bytes())?,
            period: 30,
            digits: digits,
            skew: 1,
            algorithm: OtpAlgorithm::SHA1,
            issuer: None,
            account_name: None,
        })
    }

    pub fn with_digits(&mut self, digits: usize) -> &mut Self {
        self.digits = digits;
        self
    }

    pub fn with_period(&mut self, period: u64) -> &mut Self {
        self.period = period;
        self
    }

    pub fn with_algorithm(&mut self, algorithm: OtpAlgorithm) -> &mut Self {
        self.algorithm = algorithm;
        self
    }


*/
/*
#[test]
    fn totp_rs_verify_totp_1111111109_sec() {
        use totp_rs::{Algorithm, TOTP, Secret};
        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890".as_bytes());
        // SHA256 gives 32247374
        let totp = TOTP::new(
            Algorithm::SHA256,
            8,
            0,
            30,
            Secret::Encoded(key).to_bytes().unwrap(),
        ).unwrap();
        let token = totp.generate(59);
        println!("{}", token);

    }


#[test]
    fn verify_url_parsing() {
        use url::{Host, Position, Url};
        let issue_list_url =
            Url::parse("https://github.com/rust-lang/rust/issues?labels=E-easy&state=open")
                .unwrap();

        assert!(issue_list_url.scheme() == "https");

        let otp_url = Url::parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30").unwrap();
        println!("scheme is {}", otp_url.scheme());
        println!("Host is {:?}", otp_url.host_str());

        let path = otp_url.path().trim_start_matches('/');
        println!("Trimed path is {}", &path);
        let path = urlencoding::decode(path).unwrap().to_string();

        let mut issuer: Option<String> = None;
        let mut account_name: String;
        if path.contains(':') {
            let parts = path.split_once(':').unwrap();
            issuer = Some(parts.0.to_owned());
            account_name = parts.1.to_owned();
            println!("issuer {:?}, account_name {}", issuer, account_name);
        } else {
            account_name = path;
            println!("account_name only {}", account_name);
        }

        for (key, value) in otp_url.query_pairs() {
            match key.as_ref() {
                "algorithm" => {
                    println!("Algorithm is {}", value.as_ref());
                    // algorithm = match value.as_ref() {
                    //     "SHA1" => println!("Algorithm::SHA1"),
                    //     "SHA256" => println!("Algorithm::SHA256"),
                    //     "SHA512" => println!("Algorithm::SHA512"),
                    //     _ => println!("Algorithm::NotKnown"),
                    // }
                }
                "secret" => {
                    println!("Secret is {}", value.as_ref());
                }
                "period" => {
                    println!("Period is {}", value.as_ref());
                }
                "issuer" => {
                    println!("Issuer is {}", value.as_ref());
                }

                _ => {}
            }
        }
    }


*/

/*
// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
// into a byte string
fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    Ok(BASE32_NOPAD.decode(secret.as_bytes())?)
}

fn calc_digest(decoded_secret: &[u8], counter: u64) -> Result<Vec<u8>> {
    print_crypto_lib_info();
    do_hmac_sha1(decoded_secret, &counter.to_be_bytes())
}

// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> Result<u32> {
    let offset = match digest.last() {
        Some(x) => *x & 0xf,
        None => return Err(Error::DataError("Passed digest value is invalid")),
    } as usize;

    let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
        Ok(x) => x,
        Err(_) => return Err(Error::DataError("Passed digest value is invalid")),
    };

    let code = u32::from_be_bytes(code_bytes);
    Ok((code & 0x7fffffff) % 1_000_000)
}

// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
// (HOTP) given an RFC4648 base32 encoded secret, and an integer counter.
pub fn make_hotp(secret: &str, counter: u64) -> Result<u32> {
    let decoded = decode_secret(secret)?;
    let cd = calc_digest(decoded.as_slice(), counter)?;
    encode_digest(cd.as_slice())
}

fn make_totp_helper(secret: &str, time_step: u64, skew: i64, time: u64) -> Result<u32> {
    let counter = ((time as i64 + skew) as u64) / time_step;
    make_hotp(secret, counter)
}

// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
// (TOTP) given an RFC4648 base32 encoded secret, the time step in seconds,
// and a skew in seconds.
pub fn make_totp(secret: &str, time_step: u64, skew: i64) -> Result<u32> {
    let now = SystemTime::now();
    let time_since_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;

    let d = make_totp_helper(secret, time_step, skew, time_since_epoch.as_secs())?;

    Ok(d)
}


#[test]
    fn verify_hotp() {
        init_log_lib_info();
        assert_eq!(make_hotp("BASE32SECRET3232", 0).unwrap(), 260182);
        assert_eq!(make_hotp("BASE32SECRET3232", 1).unwrap(), 55283);
        assert_eq!(make_hotp("BASE32SECRET3232", 1401).unwrap(), 316439)
    }

    #[test]
    fn verify_totp() {
        init_log_lib_info();
        assert_eq!(
            make_totp_helper("BASE32SECRET3232", 30, 0, 0).unwrap(),
            260182
        );
        assert_eq!(
            make_totp_helper("BASE32SECRET3232", 3600, 0, 7).unwrap(),
            260182
        );
        assert_eq!(
            make_totp_helper("BASE32SECRET3232", 30, 0, 35).unwrap(),
            55283
        );
        assert_eq!(
            make_totp_helper("BASE32SECRET3232", 1, -2, 1403).unwrap(),
            316439
        );
    }


////////////////////////




*/

/*
fn rc_do_hmac_sha256(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256, Sha512};

    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    for v in data {
        mac.update(v);
    }
    let result = mac.finalize();
    Ok(result.into_bytes().to_vec())
}

*/
