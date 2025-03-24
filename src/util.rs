use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::Hasher;
use std::io::Write;
use std::path::Path;

use chrono::{
    DateTime, Datelike, Duration, Local, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc,
};
use regex::Regex;
use uuid::Uuid;

use lazy_static::lazy_static;

use crate::error::Result;
use crate::{constants::EMPTY_STR, error::Error};

// TODO: Need to use data_encoding::BASE64 for encoding and decoding
use base64::{engine::general_purpose, Engine as _};

pub fn base64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    let bytes = general_purpose::STANDARD.decode(input)?;
    Ok(bytes)
}

pub fn base64_encode<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}

// Decode a UUID from a Keepass XML file
//
// The UUID in Keepass XML files is stored base 64 encoded
pub fn decode_uuid(b64uuid: &str) -> Option<Uuid> {
    let decoded = base64_decode(b64uuid).ok()?;
    Uuid::from_slice(&decoded).ok()
}

/// Encode a UUID for a Keepass XML file for kdbx4
pub fn encode_uuid(uuid: &Uuid) -> String {
    base64_encode(uuid.as_bytes())
}

// The .NET epoch is 0001-01-01T00:00:00, which is better known as DateTime.MinValue
// This is the epoch (starting point of time) used in KeePass as reference
// We need to calculate seconds with reference to this point
fn datetime_epoch() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(1, 1, 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .expect("Forming NaiveDateTime for epoh failed. Should never happen")
}

pub(crate) fn decode_datetime_b64(b64date: &str) -> Option<NaiveDateTime> {
    let decoded = base64_decode(b64date).ok()?;
    let mut bytes = [0u8; 8];
    for i in 0..usize::min(bytes.len(), decoded.len()) {
        bytes[i] = decoded[i];
    }
    //println!("====== dat bytes {:?}", u8_arr_to_i8_arr(&bytes));
    let timestamp = Duration::seconds(i64::from_le_bytes(bytes));
    datetime_epoch().checked_add_signed(timestamp)
}

// Encode a datetime for a Keepass XML file for kdbx4
pub fn encode_datetime(date: &NaiveDateTime) -> String {
    let epoch_seconds = date.signed_duration_since(datetime_epoch()).num_seconds();
    base64_encode(epoch_seconds.to_le_bytes())
}

#[allow(dead_code)]
pub fn now_local() -> NaiveDateTime {
    let now = chrono::Local::now()
        .naive_local()
        .with_nanosecond(0)
        .unwrap();
    now
}

pub fn now_utc() -> NaiveDateTime {
    let now = chrono::Utc::now().naive_utc().with_nanosecond(0).unwrap();
    now
}

// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC
#[inline]
pub fn now_utc_seconds() -> i64 {
    now_utc().and_utc().timestamp()
}

#[inline]
pub fn now_utc_milli_seconds() -> i64 {
    now_utc().and_utc().timestamp_millis()
}

// Formats the now utc time
#[allow(dead_code)]
pub fn format_utc_now(format_str: Option<&str>) -> String {
    let now: NaiveDateTime = now_utc(); // 2024-11-05 20:01:42
    let fmt_str = if let Some(s) = format_str {
        s
    } else {
        // "%d %b %Y %H:%M:%S" This will print 05 Nov 2024

        // Formatted string is of form 2024-11-05 20:05:18
        "%Y-%m-%d %H:%M:%S"
    };
    now.format(fmt_str).to_string()
}

// We get the secs part of SystemTime ignoring nanosecs
pub fn system_time_to_seconds(system_time: std::time::SystemTime) -> u64 {
    system_time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or_else(|_| 0, |d| d.as_secs())
}

// Creates the SystemTime instance from the secs ignoring nanosecs
pub fn seconds_to_system_time(secs: u64) -> std::time::SystemTime {
    // This also works with chrono 0.4.38 not with the earlier 0.4.24
    // let dt = chrono::DateTime::from_timestamp(secs as i64,0).unwrap();
    // dt.into()

    // See doc https://doc.rust-lang.org/std/time/struct.SystemTime.html#associatedconstant.UNIX_EPOCH
    // where it is mentioned to get SystemTime from a duration
    // "using UNIX_EPOCH + duration can be used to create a SystemTime instance to represent another fixed point in time"
    std::time::UNIX_EPOCH + std::time::Duration::new(secs, 0)
}

// See https://docs.rs/chrono/latest/chrono/format/strftime/index.html
// for details on various format specifiers

// Converts a NaiveDateTime to a formatted str in local tz
// NaiveDateTime is  ISO 8601 combined date and time without timezone
pub fn _format_utc_naivedatetime_to_local(
    naive: &NaiveDateTime,
    format_str: Option<&str>,
) -> String {
    // First we need to convert the NaiveDateTime to represent UTC datetime
    let utc_date_time: DateTime<Utc> = Utc
        .from_local_datetime(&naive)
        .single()
        .map_or(Utc::now(), |d| d);

    let local_date_time: DateTime<Local> = utc_date_time.with_timezone(&Local);
    // another way of getting the same local time - Local.from_utc_datetime(&utc_date_time.naive_local());
    if let Some(fmt_str) = format_str {
        local_date_time.format(fmt_str).to_string()
    } else {
        local_date_time.format("%d %b %Y %H:%M:%S").to_string()
    }
}

// Add years to the given date and returns the new date if addition is successful
// Otherwise the old date is returned with any change
pub fn add_years<DateTime: Datelike>(old_dt: DateTime, year: i32) -> DateTime {
    let dt = old_dt.with_year(old_dt.year() + year);
    if let Some(d) = dt {
        return d;
    } else {
        old_dt
    }
}

// Add months to the given date and returns the new date if addition is successful
// Otherwise the old date is returned with any change
#[allow(dead_code)]
pub fn add_months<DateTime: Datelike>(old_dt: DateTime, months: u32) -> DateTime {
    let total_months = old_dt.month() + months;
    //We need to determine the number of years and months to add separately
    //if the total months exceeds 12. Otherwise with_month will not add months
    if total_months > 12 {
        let years = total_months / 12;
        let rem_months = total_months % 12;
        let ndt = add_years(old_dt, years as i32);
        return add_months(ndt, rem_months);
    } else {
        let dt = old_dt.with_month(total_months);
        if let Some(d) = dt {
            return d;
        } else {
            return old_dt;
        }
    }
}

pub fn decompress(compressed_data: &[u8]) -> Result<Vec<u8>> {
    let mut writer = Vec::new();
    let mut decoder = flate2::write::GzDecoder::new(writer);
    decoder.write_all(&compressed_data)?;
    decoder.try_finish()?;
    writer = decoder.finish()?;

    Ok(writer)
}

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), Compression::new(6));
    e.write_all(data).unwrap();
    let compressed_bytes = e.finish().unwrap();
    Ok(compressed_bytes)
}

pub fn compress_with_fixed_timestamp(data: &[u8]) -> Result<Vec<u8>> {
    let mut gz = flate2::GzBuilder::new()
        .mtime(10)
        .write(Vec::new(), flate2::Compression::default());
    gz.write_all(data)?;
    Ok(gz.finish()?)
}

// Print digest result as hex string and name pair
// pub fn print_result(sum: &[u8], name: &str) {
//     for byte in sum {
//         print!("{:02x}", byte);
//     }
//     println!("\t{}", name);
// }

/// Generates a hash key based on the bytes data of any string passed
pub fn string_to_simple_hash(name: &str) -> u64 {
    let data: &[u8] = name.as_bytes();
    let mut hasher = DefaultHasher::new();
    hasher.write(data);
    hasher.finish()
}

// Forms a key to use in all Key Chain/Store calls
#[inline]
pub fn formatted_key(db_key: &str) -> String {
    format!("OKP-{}", string_to_simple_hash(db_key))
        .as_str()
        .into()
}

#[allow(dead_code)]
pub fn to_hex_string(data: &[u8]) -> String {
    let mut output = String::new();

    for byte in data {
        output.push_str(&format!("{:x}", byte))
    }
    output
}

#[allow(dead_code)]
pub fn to_hex_string_with_space(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b).to_string())
        .collect::<Vec<String>>()
        .join(" ")
}

#[allow(dead_code)]
pub fn as_hex_array_formatted(data: &[u8]) -> String {
    // Upper case
    // [ 0x68, 0x65,0x6C,0x6C, 0x6F,..]
    // format!("{:#04X?}", data)

    // Lower case
    // gives something like [ 0x68, 0x65,0x6C,0x6C,0x6F,]
    format!("{:#04X?}", data)
}

#[allow(dead_code)]
pub fn u8_arr_to_i8_arr(data: &[u8]) -> Vec<i8> {
    let v1: Vec<i8> = data.iter().map(|x| *x as i8).collect();
    v1
}

//Need to use some generic type
#[allow(dead_code)]
pub fn u8_32arr_to_i8_32arr(data: &[u8]) -> [i8; 32] {
    use std::mem;
    let d1 = slice_as_array!(data, [u8; 32]).expect("error");
    let ir = unsafe { mem::transmute::<[u8; 32], [i8; 32]>(*d1) };
    ir
}

//Need to work not on these
#[allow(dead_code)]
pub fn to_i64(d: &[u8]) -> std::result::Result<i64, &'static str> {
    if let Some(n) = slice_as_array!(d, [u8; 8]) {
        Ok(i64::from_le_bytes(*n))
    } else {
        Err("Conversion to i64 failed")
    }
}

pub fn to_u64(d: &[u8]) -> std::result::Result<u64, &'static str> {
    if let Some(n) = slice_as_array!(d, [u8; 8]) {
        Ok(u64::from_le_bytes(*n))
    } else {
        Err("Conversion to u64 failed")
    }
}

pub fn to_i32(d: &[u8]) -> std::result::Result<i32, &'static str> {
    if let Some(n) = slice_as_array!(d, [u8; 4]) {
        Ok(i32::from_le_bytes(*n))
    } else {
        Err("Conversion to i32 failed")
    }
}

pub fn to_u32(d: &[u8]) -> std::result::Result<u32, &'static str> {
    if let Some(n) = slice_as_array!(d, [u8; 4]) {
        Ok(u32::from_le_bytes(*n))
    } else {
        Err("Conversion to u32 failed")
    }
}

// Removes all contents of a dir including sub dirs
pub fn remove_dir_contents<P: AsRef<Path>>(path: P) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_dir() {
            remove_dir_contents(&path)?;
            fs::remove_dir(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[inline]
pub fn empty_str() -> String {
    EMPTY_STR.to_string()
}

// Called to get just the file name from the full path
pub fn file_name(full_file_uri: &str) -> Option<String> {
    let p = Path::new(full_file_uri);
    p.file_name().map(|s| s.to_string_lossy().to_string())
}

// From https://users.rust-lang.org/t/solved-how-to-split-string-into-multiple-sub-strings-with-given-length/10542/9
// This takes care of any utf-8
// For now this is sufficent
pub fn sub_strings(string: &str, sub_len: usize) -> Vec<&str> {
    let mut subs = Vec::with_capacity(string.len() / sub_len);
    let mut iter = string.chars();
    let mut pos = 0;

    while pos < string.len() {
        let mut len = 0;
        for ch in iter.by_ref().take(sub_len) {
            len += ch.len_utf8();
        }
        subs.push(&string[pos..pos + len]);
        pos += len;
    }
    subs
}

#[inline]
pub fn parse_attachment_hash(data_hash_str: &str) -> Result<u64> {
    let data_hash = data_hash_str.parse::<u64>().map_err(|e| {
        Error::UnexpectedError(format!("Data hash str to u64 conversion failed - {} ", e))
    })?;
    Ok(data_hash)
}

lazy_static! {
    pub static ref RE_SPACES: Regex = Regex::new(r"\s+").unwrap();
}
// Copied from once_cell https://docs.rs/once_cell/latest/once_cell/index.html#lazily-compiled-regex
// macro_rules! regex {
//     ($re:literal $(,)?) => {{
//         static RE: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
//         RE.get_or_init(|| regex::Regex::new($re).unwrap())
//     }};
// }

#[inline]
pub fn strip_spaces(string_with_spaces: &str) -> String {
    // regex macro can also be used
    // let re = regex!(r"\s+"); re.replace_all(string_with_spaces, "");

    let replaced_string = RE_SPACES.replace_all(string_with_spaces, "");
    replaced_string.to_string()
}

// To see logging output during unit testing
#[test]
pub fn init_test_logging() {
    let _ = env_logger::builder()
        // Include all events in tests
        .filter_level(log::LevelFilter::max())
        // Ensure events are captured by `cargo test`
        .is_test(true)
        // Ignore errors initializing the logger if tests race to configure it
        .try_init();
}

// const TAGS_SEPARATORS: [char; 2] = [';', ','];
// /// Splits tags string into vector of tags
// pub fn split_tags(tags: &str) -> Vec<String> {
//     let splits = tags.split(&TAGS_SEPARATORS[..]);
//     splits
//         .filter(|w| !w.is_empty())
//         .map(|w| w.trim().into())
//         .collect::<Vec<String>>()
// }

pub mod from_or_to {
    // This sub module is just syntactic sugar
    pub mod string {
        use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

        // Handles any type 'T' that is parseable from string
        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: std::str::FromStr,
            <T as std::str::FromStr>::Err: std::fmt::Display,
        {
            String::deserialize(deserializer)?
                .parse::<T>()
                .map_err(|e| D::Error::custom(format!("{}", e)))
        }

        pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
            T: std::fmt::Display,
        {
            format!("{}", value).serialize(serializer)
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[allow(unused)]
mod tests {
    use super::*;
    #[test]
    fn decode_uuid_sample_b64str() {
        let b64_str = "3aBY+AcLQmiPas0vjK2zng==";
        let u = decode_uuid(b64_str);
        assert_eq!(u.is_some(), true);
        println!("Uuid is {}", u.unwrap());
        assert_eq!(
            u.unwrap().to_string(),
            "dda058f8-070b-4268-8f6a-cd2f8cadb39e"
        );
    }

    #[test]
    fn decode_uuid_sample_b64str_1() {
        use data_encoding::BASE64;

        let b64_str = "3aBY+AcLQmiPas0vjK2zng==";
        let decoded = BASE64.decode(b64_str.as_bytes()).unwrap();
        let u = Uuid::from_slice(&decoded).ok();
        assert_eq!(u.is_some(), true);
        println!("Uuid is {}", u.unwrap());
        assert_eq!(
            u.unwrap().to_string(),
            "dda058f8-070b-4268-8f6a-cd2f8cadb39e"
        );
    }

    #[test]
    fn decode_uuid_to_none_sample() {
        let s = "dda058f8-070b-4268-8f6a-cd2f8cadb39e";
        let u = decode_uuid(s);
        assert_eq!(u.is_none(), true);
        //println!("Uuid is {}", u.unwrap());
    }

    #[test]
    fn encode_uuid_to_b64() {
        let ur = Uuid::parse_str("dda058f8-070b-4268-8f6a-cd2f8cadb39e");
        assert_eq!(ur.is_ok(), true);
        let u = encode_uuid(&ur.unwrap());
        assert_eq!(u == "3aBY+AcLQmiPas0vjK2zng==", true);
    }

    #[test]
    fn encode_uuid_to_b64_1() {
        use data_encoding::BASE64;
        let ur = Uuid::parse_str("dda058f8-070b-4268-8f6a-cd2f8cadb39e");
        assert_eq!(ur.is_ok(), true);
        let u = BASE64.encode(ur.unwrap().as_bytes());
        assert_eq!(u == "3aBY+AcLQmiPas0vjK2zng==", true);
    }

    #[allow(dead_code)]
    use chrono::{DateTime, Datelike, Duration, Local, NaiveTime, TimeZone, Utc};

    #[test]
    fn verify_decode_datetime_b64() {
        let ndt = decode_datetime_b64("mNxg1g4AAAA=");
        println!("dt is {:?}", ndt); //Some(2020-05-27T22:11:36)

        let dt = ndt.unwrap();
        assert_eq!(
            dt.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "2020-05-27T22:11:36"
        );

        //println!( "d is {}" , dt);
        assert_eq!(dt, NaiveDate::from_ymd(2020, 5, 27).and_hms(22, 11, 36));
        assert_eq!(dt.date(), NaiveDate::from_ymd(2020, 5, 27));
        assert_eq!(dt.time(), NaiveTime::from_hms(22, 11, 36));

        let ldt = Local.from_utc_datetime(&dt); //2020-05-27T15:11:36-07:00 , 7.00 hours UTC time - PDT time
        println!("ldt is {:?}", ldt);
        assert_eq!(ldt.date(), Local.ymd(2020, 5, 27));
        assert_eq!(ldt.time(), NaiveTime::from_hms(15, 11, 36));

        //assert_eq!(d, Some("2020-05-27T22:11:36"));
        // if let Some(d) = dt {
        //     let dt1 = DateTime::<Utc>::from_utc(d, Utc);
        //     println!("dt1 is {:?}", dt1);
        //     let dt2 = dt1.with_timezone(&chrono_tz::US::Pacific);
        //     println!("dt2 is {:?}", dt2);
        //     //println!(" offset {}", TimeZone::offset_from_utc_datetime(d));
        // }

        // let dt: DateTime<Local> = Local::now();
        // println!("dt is {:?}", dt);
        // if let Some(d) = dt {
        //     let dt3 =  Local.from_utc_datetime(&d);//Local.isoywd(2015, 20, Weekday::Fri).to_string();

        //     println!("dt3 is {:?}", dt3);
        // }
    }

    #[test]
    fn verify_utc_parsing() {
        let dt = Utc.ymd(2022, 01, 04).and_hms_milli(1, 37, 8, 811);

        //The Javascript Date fn creates datetime  in UTC timezone
        //(.toISOString (js/Date.)) returns UTC time 2022-01-04T01:37:08.811Z
        let parsed_dt = "2022-01-04T01:37:08.811Z".parse::<DateTime<Utc>>().unwrap();

        //println!("UTC Dt {:?}", parsed_dt);
        let parsed_dt_pacific = parsed_dt.with_timezone(&chrono_tz::US::Pacific);
        //println!("Parsed dt in Pacific TimeZone {:?}", parsed_dt_pacific);

        let n1 = parsed_dt.checked_add_signed(Duration::weeks(52));
        //println!("New Dt {:?}", n1);

        // let n2 = Utc.ymd(parsed_dt.year(),
        //     parsed_dt.month(),
        //     parsed_dt.day()).and_hms_milli(parsed_dt.hour(),parsed_dt.min(),parsed_dt.sec(),parsed_dt.milli());

        //let n2 = add_years(parsed_dt,10);//parsed_dt.with_year(parsed_dt.year()+1);
        let n2 = add_months(parsed_dt, 23); //parsed_dt.with_year(parsed_dt.year()+1);

        //println!("New Dt2 {:?}", n2);

        assert_eq!(dt == parsed_dt, true);
    }

    #[test]
    fn verify1() {
        //DateTime::<Utc>
        //NaiveDateTime::new(date, time)

        let d1 = now_utc(); // 2024-11-05 20:01:42
        let s1 = d1.format("%d %b %Y %H:%M:%S").to_string();
        let s1 = d1.format("%Y-%m-%d %H:%M:%S").to_string();
        println!("d1 is {}", &s1);
    }

    #[test]
    fn verify_datetime_local_format() {
        // Experiment to show UTC and Local now calls. The Local now should be based on the system timezone
        // and accordingly it is expected have some offsets
        // Howver, in case of Mac OS 12.6.2 (as on 01 Jan 2023) in M1 machine, the Local returns the same time as Utc.
        // The same works fine in X86_64 mac with os 10.15+
        // See some related issues in chrono here
        // https://github.com/chronotope/chrono/issues/922,
        let d1 = Utc::now();
        println!("Formatted {}", d1.format("%Y-%m-%dT%H:%M:%S").to_string());
        let d2 = Local::now();
        let d3 = Local.from_local_datetime(&d2.naive_local());
        println!(
            "utc dt is {},str dt {}, tz is {}, offset {}",
            d1,
            d1.to_string(),
            d1.timezone(),
            d1.offset()
        );
        println!(
            "local dt is {}, tz is {:?} , offset {}",
            d2,
            d2.timezone(),
            d2.offset()
        ); // d2 should have some offsets

        println!("d3 is {:?}", d3);

        // This is reflects proper offsets from Utc
        let parsed_dt_pacific = d1.with_timezone(&chrono_tz::US::Pacific);
        println!("Parsed dt in Pacific TimeZone {:?}", parsed_dt_pacific);
        let offset_in_sec = d2.offset().local_minus_utc();
        println!("offset_in_sec is {}", offset_in_sec);

        println!(
            "parsed_dt_pacific offset  is {}",
            parsed_dt_pacific.offset()
        );

        //Following tests will fail while rumming in Mac m1 with os 12.6+. See above
        /*
        let naive_dt: NaiveDateTime = NaiveDate::from_ymd(2016, 7, 8).and_hms(9, 10, 11);
        println!( "dt is {}",naive_dt);
        println!("Date {}", naive_dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

        let date_time: DateTime<Utc> = Utc.from_local_datetime(&naive_dt).unwrap();
        //let date_time: DateTime<Utc> = Utc.from_utc_datetime(&naive_dt);
        println!( "UTC date_time is {}",date_time.format("%Y-%m-%dT%H:%M:%S"));
        assert_eq!("2016-07-08T09:10:11" == date_time.format("%Y-%m-%dT%H:%M:%S").to_string(), true);

        let local_date_time: DateTime<Local> = date_time.with_timezone(&Local);
        println!("TZ is {:?}",local_date_time.timezone());
        println!( "Local date_time is {}",local_date_time.format("%Y-%m-%dT%H:%M:%S"));
        println!( "Local date_time is {}",local_date_time.format("%d %b %Y %H:%M:%S %Z")); //%Z is not working, it puts -07:00 instead PST

        let formated = format_utc_naivedatetime_to_local(&naive_dt,None);
        //println!( "Local date_time formated as  {}",formated);
        assert_eq!("08 Jul 2016 02:10:11" == formated, true);

        let formated = format_utc_naivedatetime_to_local(&naive_dt,Some("%Y-%m-%dT%H:%M:%S"));
        assert_eq!("2016-07-08T02:10:11" == formated, true);

        //let v = Local.from_utc_datetime(&date_time.naive_local());
        //println!("v is {}",v);

        let formated = format_utc_naivedatetime_to_local(&naive_dt,Some("%Y-%m-%d %I:%M:%S %p"));
        println!("{}",formated);

        */
    }

    #[test]
    fn verify_add_years_months_weeks_days() {
        let parsed_dt = "2022-01-04T01:37:08.811Z".parse::<DateTime<Utc>>().unwrap();

        let ndt = add_years(parsed_dt, 10);
        assert_eq!(ndt.year(), 2032); // Year = 2022+10
                                      // All other parts of 'ndt' are the same as in 'parsed_dt'
                                      //Month remains the same
        assert_eq!(ndt.month(), 1);
        //Day remains the same
        assert_eq!(ndt.day(), 4);
        assert_eq!(ndt.hour(), 01);
        assert_eq!(ndt.minute(), 37);
        assert_eq!(ndt.second(), 08);

        //Let us add few months to an existing date
        //Added 23 months to the currrent month 1
        let ndt = add_months(parsed_dt, 23);
        assert_eq!(ndt.year(), 2024);
        assert_eq!(ndt.month(), 1);
        assert_eq!(ndt.day(), 4);
        assert_eq!(ndt.hour(), 01);
        assert_eq!(ndt.minute(), 37);
        assert_eq!(ndt.second(), 08);

        //This will add 24 months to the current month 1
        //Year and month will change and all other components will remain the same
        let ndt = add_months(parsed_dt, 24);
        assert_eq!(ndt.year(), 2024); //
        assert_eq!(ndt.month(), 2);
        assert_eq!(ndt.day(), 4);
        assert_eq!(ndt.hour(), 01);
        assert_eq!(ndt.minute(), 37);
        assert_eq!(ndt.second(), 08);

        //Adding weeks and days
        let ndt = parsed_dt.checked_add_signed(Duration::weeks(52)).unwrap();
        //println! ("New ndt {:?}", ndt);
        assert_eq!(ndt.year(), 2023); //Year changed
        assert_eq!(ndt.month(), 1); //Same month
        assert_eq!(ndt.day(), 3); //Day changed from 04 to 03
        assert_eq!(ndt.hour(), 01); //Same
        assert_eq!(ndt.minute(), 37); //Same
        assert_eq!(ndt.second(), 08); //Same

        let ndt = parsed_dt.checked_add_signed(Duration::days(365)).unwrap();
        println!("New ndt {:?}", ndt);
        assert_eq!(ndt.year(), 2023); //Year changed
        assert_eq!(ndt.month(), 1); //Same month
        assert_eq!(ndt.day(), 4); // Same
        assert_eq!(ndt.hour(), 01); //Same
        assert_eq!(ndt.minute(), 37); //Same
        assert_eq!(ndt.second(), 08); //Same
    }

    use super::system_time_to_seconds;

    #[test]
    fn verify_system_time_secs() {
        use std::time::SystemTime;
        let s1 = SystemTime::now();
        println!("S1 is  {:?}", &s1);

        let secs = system_time_to_seconds(s1);
        println!("Secs {}", &secs);

        let s2 = super::seconds_to_system_time(secs);
        println!("S2 is  {:?}", &s2);

        assert_eq!(
            s1.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            s1.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
        );
    }

    #[test]
    fn verify_compress_decompress() {
        let v1 = "Test message ".as_bytes();
        let c_v1 = compress(&v1).unwrap();

        let d_v1 = decompress(&c_v1).unwrap();
        assert_eq!(d_v1 == v1, true);

        // gzip adds timestamp. As a result c_v1 != c_v2
        // use std::{thread, time};
        // let ten_millis = time::Duration::from_millis(1000);
        // thread::sleep(ten_millis);
        // let c_v2 = compress(&v1).unwrap();
        // assert_ne!(c_v1 == c_v2, true);
    }

    #[test]
    fn verify_compress_with_options() {
        let v1 = "Test message ".as_bytes();
        let c_v1 = compress_with_fixed_timestamp(&v1).unwrap();

        let d_v1 = decompress(&c_v1).unwrap();
        assert_eq!(d_v1 == v1, true);

        // gzip adds fixed timestamp. As a result c_v1 == c_v2
        use std::{thread, time};
        let ten_millis = time::Duration::from_millis(1000);
        thread::sleep(ten_millis);
        let c_v2 = compress_with_fixed_timestamp(&v1).unwrap();
        assert_eq!(c_v1 == c_v2, true);
    }

    #[test]
    fn verify_compress_decompress_timing() {
        let test_file = "/Users/jeyasankar/mytemp/Test1/compression_test_data_bin";
        let mut f = fs::File::open(test_file).unwrap();
        let mut buf: Vec<u8> = vec![];
        std::io::Read::read_to_end(&mut f, &mut buf).unwrap();
        println!("Size of buf is {}", buf.len());

        let start = std::time::Instant::now();
        let c_v1 = compress(&buf).unwrap();
        println!("Size of compressed data  is {}", c_v1.len());
        println!("Compression took {} seconds ", start.elapsed().as_secs());

        let start = std::time::Instant::now();
        let c_v2 = decompress(&c_v1).unwrap();
        println!("Size of decompressed data  is {}", c_v2.len());
        println!("Dcompression took {} seconds ", start.elapsed().as_secs());
    }

    #[test]
    fn hex_str_test() {
        let b: Vec<u8> = vec![12, 3, 44, 7, 6, 22, 34];
        use hex;
        println!("{:x?}", &b);
        assert_eq!("0c032c07061622", hex::encode(&b));
        assert_eq!(&b, &hex::decode("0c032c07061622").unwrap());
    }

    #[test]
    fn verify_remove_spaces() {
        //let RE_SPACES: Regex = Regex::new(r"\s+").unwrap();
        let s = " ba3 r2 J45 ";

        let s1 = strip_spaces(s);
        println!("s1 is {}", s1);
        assert_eq!(s1, "ba3r2J45");

        let s2 = "";
        assert_eq!(strip_spaces(s2).is_empty(), true);
    }
}

/*
#[test]
    fn decode_datetime_b64_experiment1() {
        let ndt = decode_datetime_b64("L0Fc2g4AAAA="); //  empty string results in Some(0001-01-01T00:00:00)
        println!("dt is {:?}", ndt); //Some(2020-05-27T22:11:36)

        let dt = ndt.unwrap();
        println!("Date {}", dt.format("%Y-%m-%dT%H:%M:%S").to_string());

        println!("{}", now_utc());
    }
 */
