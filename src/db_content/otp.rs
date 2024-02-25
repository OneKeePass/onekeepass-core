use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{crypto::{hmac_sha1_from_slice, hmac_sha256_from_slice, hmac_sha512_from_slice, print_crypto_lib_info}, error::{Error, Result}};

use data_encoding::BASE32_NOPAD;
use url::Url;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum OtpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

#[derive(Debug, Clone)]
pub(crate) struct OtpData {
    // non-encoded value
    // Any base32 encoded incoming value needs to be decoded
    pub(crate) decoded_secret: Vec<u8>, 
    pub(crate) period: u64,
    pub(crate) digits: usize,
    pub(crate) algorithm: OtpAlgorithm,
    pub(crate) issuer: Option<String>,
    pub(crate) account_name: Option<String>,
}

fn system_time() -> Result<u64> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(t)
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
            _ => Err(Error::DataError("()")),
        }
    }
}

impl OtpData {
    pub fn new(secret: &str) -> Result<OtpData> {
        Ok(OtpData {
            decoded_secret: BASE32_NOPAD.decode(secret.as_bytes())?,
            period: 30,
            digits: 6,
            algorithm: OtpAlgorithm::SHA1,
            issuer: None,
            account_name: None,
        })
    }

    pub fn try_from_url(otp_url: &str) -> Result<OtpData> {
        let mut algorithm = OtpAlgorithm::SHA1;
        let mut digits = 6;
        let mut period = 30;
        let mut secret = Vec::new();
        let mut issuer: Option<String> = None;
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
                        Error::OtpUrlParseError(format!("Invalid digits value {}", value))
                    })?;
                }
                "period" => {
                    period = value.parse::<u64>().map_err(|_| {
                        Error::OtpUrlParseError(format!("Invalid period value {}", value))
                    })?;
                }
                "secret" => {
                    println!("Secret is {}", value.as_ref());
                    let s = value.as_ref();
                    secret = BASE32_NOPAD.decode(s.as_bytes())?;
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

        Ok(OtpData {
            algorithm,
            decoded_secret: secret,
            period,
            digits,
            issuer,
            account_name,
        })
    }

    // Will sign the given timestamp
    pub fn sign(&self, time: u64) -> Result<Vec<u8>> {
        self.algorithm.sign(
            self.decoded_secret.as_ref(),
            (time / self.period).to_be_bytes().as_ref(),
        )
    }

    // Will generate a token given the provided timestamp in seconds
    pub fn generate(&self, time: u64) -> Result<String> {
        let result: &[u8] = &self.sign(time)?;
        let offset = (result.last().unwrap() & 15) as usize;
        #[allow(unused_mut)]
        let mut result =
            u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;

        let s = format!(
            "{1:00$}",
            self.digits,
            result % 10_u32.pow(self.digits as u32)
        );

        Ok(s)
    }

    // Generate a token from the current system time
    pub fn generate_current(&self) -> Result<String> {
        let t = system_time()?;
        self.generate(t)
    }

    // Returns the timestamp of the first second for the next period
    // given the provided timestamp in seconds
    fn next_period(&self, time: u64) -> u64 {
        let period = time / self.period;
        (period + 1) * self.period
    }

    // Returns the timestamp of the first second of the next step
    // According to system time
    fn next_step_current(&self) -> Result<u64> {
        let t = system_time()?;
        Ok(self.next_period(t))
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
    use super::OtpData;
    use crate::{crypto::init_log_lib_info, db_content::otp::OtpAlgorithm};


    #[test]
    fn verify_totp_59_sec() {
        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890".as_bytes());
        // Encoded key is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        println!("Encoded key is {}", key);
        let mut od = OtpData::new(key.as_str()).unwrap();
        od.digits = 8;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(59),
            od.ttl()
        );

        let key = data_encoding::BASE32_NOPAD.encode("12345678901234567890123456789012".as_bytes());
        let mut od = OtpData::new(key.as_str()).unwrap();
        od.digits = 8;
        od.algorithm = OtpAlgorithm::SHA256;
        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate(59),
            od.ttl()
        );

        let key = data_encoding::BASE32_NOPAD.encode("1234567890123456789012345678901234567890123456789012345678901234".as_bytes());
        let mut od = OtpData::new(key.as_str()).unwrap();
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
        let mut od = OtpData::new(key.as_str()).unwrap();
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
        let od = OtpData::new("BASE32SECRET3232").unwrap();
        println!("Od is {:?}", od);

        println!(
            "od generate  is {:?} with ttl {:?}",
            od.generate_current(),
            od.ttl()
        );
    }
}
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
