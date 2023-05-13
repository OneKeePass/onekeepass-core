mod constants;
mod crypto;
mod db;
mod form_data;
mod password_generator;
mod searcher;
mod util;
mod xml_parse;

pub mod error;

pub mod db_content;
pub mod db_service;

#[macro_use]
extern crate slice_as_array;
extern crate lazy_static;
extern crate log;

// use once_cell::sync::Lazy;
// use std::{
//     collections::HashMap,
//     sync::{Arc, Mutex},
//   };

// type DbFilesStore = Arc<Mutex<HashMap<String, String>>>;

// fn db_files() -> &'static DbFilesStore  {
//     static DB_STORE: Lazy<DbFilesStore> = Lazy::new(Default::default);
//   &DB_STORE
// }

// pub fn load_kdbx(name:String, data:String)  {
//     let mut store = db_files().lock().unwrap();
//     store.insert(name, data);
// }

// pub fn groups_summary_data(name:&String) -> String {
//     let store = db_files().lock().unwrap();
//     match store.get(name) {
//         Some(x) => x.clone(),
//         None => "None".to_string()
//     }
// }

pub fn my_command() {}

//Need to use " cargo test -- --nocapture " to see println! output in the console
#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn test1() {
        let v1 = [2, 3, 4];
        let v = &v1[..];
        //let u8slice = unsafe { &*(i8slice as *[i8] as *[u8]) };
        //let i8v = unsafe { &*(v1 as *[u8] as *[i8]) };
        println!("v is {:?}", v);

        use std::mem;
        unsafe {
            //let a = [0u8, 0u8, 0u8, 0u8];
            let a: [u8; 4] = [200, 3, 4, 5];
            let b = mem::transmute::<[u8; 4], [i8; 4]>(a);
            println!("b is {:?}", b);
        }

        assert_eq!(crate::constants::SIG1, 0x9AA2_D903);
    }

    #[test]
    #[ignore]
    fn test2() {
        use crate::crypto::calculate_hash;

        let mut v: Vec<u8> = Vec::new();
        for i in &[3, 4] {
            v.push(*i as u8);
        }
        let r = calculate_hash(&vec![v]).unwrap();

        println!("r is {:?}", r);

        use std::mem;
        let ir = unsafe {
            let a: [u8; 32] = [
                119, 178, 202, 206, 16, 219, 78, 34, 91, 12, 54, 53, 141, 51, 90, 216, 150, 149,
                219, 40, 117, 167, 63, 172, 101, 181, 14, 12, 145, 177, 251, 147,
            ];
            mem::transmute::<[u8; 32], [i8; 32]>(a)
        };
        println!("ir is {:?}", ir);
        assert_eq!(crate::constants::SIG1, 0x9AA2_D903);
    }
    #[test]
    #[ignore]
    fn test3() {
        use crate::util::u8_arr_to_i8_arr;
        let a: [u8; 32] = [
            194, 34, 140, 83, 212, 130, 62, 166, 51, 149, 141, 101, 197, 151, 231, 88, 170, 95,
            181, 85, 142, 115, 141, 154, 141, 98, 156, 111, 150, 98, 164, 104,
        ];

        let out = u8_arr_to_i8_arr(&a[..]);
        println!("out is {:?}", out);
        assert_eq!(crate::constants::SIG1, 0x9AA2_D903);
    }

    #[test]
    #[ignore]
    fn test4() {
        //let a:u64 = 488976;

        let c = crate::constants::PAYLOAD_BLOCK_SIZE;

        println!("c is {:?}", c);

        assert_eq!(0, 0);
    }
}
