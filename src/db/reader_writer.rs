use std::cmp;

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use log::{debug, error};

use crate::constants;
use crate::constants::{header_type, inner_header_type, PAYLOAD_BLOCK_SIZE};
use crate::crypto;
use crate::crypto::ContentCipher;
use crate::crypto::ProtectedContentStreamCipher;
use crate::error::{Error, Result};
use crate::util;

use crate::xml_parse;

use crate::db::kdbx_file::KdbxFile;

pub struct KdbxFileReader<'a, T>
where
    T: Read + Seek,
{
    reader: &'a mut T,
    pub(crate) kdbx_file: KdbxFile,
    header_data_start_position: u64,
    header_data_end_position: u64,
}

#[allow(dead_code)]
impl<'a, T: Read + Seek> KdbxFileReader<'a, T> {
    pub(crate) fn new(reader: &'a mut T, kdbx_file: KdbxFile) -> KdbxFileReader<'a, T> {
        KdbxFileReader {
            reader,
            kdbx_file,
            header_data_start_position: 0,
            header_data_end_position: 0,
        }
    }

    // Reads the content of kdbx db, parses headers, decrypts payload, parses xml content into in memory struct
    pub(crate) fn read(&mut self) -> Result<()> {
        debug!("Starting the dataabse read_file_signature call");
        self.read_file_signature()?;
        self.read_header()?;
        self.verify_stored_hash()?;
        self.kdbx_file.compute_all_keys(false)?; //Uses password and key file content
        self.verify_header_hmac()?;
        let mut buf = self.read_hmac_data_blocks()?;
        buf = self.decrypt_data(&buf)?;
        buf = self.split_inner_header_xml_content(&buf)?;
        // buf now has the xml bytes data
        self.read_xml_content(&buf)?;

        Ok(())
    }

    /// Reads the signatures and version of the kbdx file and verifies that they are valid
    fn read_file_signature(&mut self) -> Result<()> {
        let mut buffer = [0; 4];
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let sig1 = u32::from_le_bytes(buffer); // u32 value 2594363651
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let sig2 = u32::from_le_bytes(buffer); // u32 value  3041655655
        self.reader.read_exact(&mut buffer)?; // 4 bytes
        let ver = u32::from_le_bytes(buffer); // u32 value 262144,hex 40000  (for 4.1 the values are 262145, 40001)

        // TODO: Need to modifiy to verify (using higher 4 bytes ?) ver as any 4.x instead of the specific 4.0 or 4.1
        match (sig1, sig2, ver) {
            (constants::OLD_SIG1, constants::OLD_SIG2, _) => {
                return Err(Error::OldUnsupportedKeePass1);
            }

            (_, _, v)
                if v == constants::VERSION_20
                    || v == constants::VERSION_30
                    || v == constants::VERSION_31 =>
            {
                return Err(Error::OldUnsupportedKdbxFormat);
            }

            (constants::SIG1, constants::SIG2, constants::VERSION_40) => (),
            (constants::SIG1, constants::SIG2, constants::VERSION_41) => (),
            _ => {
                return Err(Error::InvalidKeePassFile);
            }
        };

        //We should have read 12 bytes from start at this point
        //Need to include these 12 bytes to calculate the header hash later and accordingly we
        //reset the stream postion to 0 and hash(12byes+header data) verification is done after reading the header data
        self.header_data_start_position = 0;
        Ok(())
    }

    fn read_header(&mut self) -> Result<()> {
        let mut header_end = true;
        while header_end {
            let mut buf = [0; 1];
            self.reader.read_exact(&mut buf)?;
            let entry_type = buf[0];
            match entry_type {
                header_type::END_OF_HEADER => {
                    //We need to read the Header end marker which is [13, 10, 13, 10]
                    //so that stream position is correct.
                    self.read_header_field()?; //Just discard these 4 bytes
                    header_end = false;
                }
                header_type::CIPHER_ID => {
                    self.kdbx_file.main_header.cipher_id = self.read_header_field()?;
                }
                header_type::COMPRESSION_FLAGS => {
                    self.kdbx_file.main_header.compression_flag =
                        util::to_i32(&self.read_header_field()?)?;
                }
                header_type::MASTER_SEED => {
                    self.kdbx_file.main_header.master_seed = self.read_header_field()?;
                }
                header_type::ENCRYPTION_IV => {
                    self.kdbx_file.main_header.encryption_iv = self.read_header_field()?;
                }
                header_type::KDF_PARAMETERS => {
                    //self.kdbx_file.main_header.kdf_parameters_raw = self.read_header_field()?;
                    //cannot borrow `*self` as mutable more than once at a time
                    //self.kdbx_file.main_header.extract_kdf_parameters(&self.read_header_field()?)?;
                    let v = &self.read_header_field()?;
                    self.kdbx_file.main_header.extract_kdf_parameters(&v)?;
                }
                header_type::COMMENT => {
                    self.kdbx_file.main_header.comment = self.read_header_field()?;
                }
                header_type::PUBLIC_CUSTOM_DATA => {
                    //The data read for the PublicCustomData is a VariantDictionary similar to KDF parameters.
                    //At this time, as OneKeePass (OKP) does not require any public custom data and no plugins are supported by OKP
                    //So the complete PublicCustomData byetes are just read and stored in a vec. If we need to use this field any time in future,
                    //we need to deserilaize and serilalize similar to KDF parameters to extract individual {Key,Object} values from these bytes
                    self.kdbx_file.main_header.public_custom_data = self.read_header_field()?;
                }
                _ => {
                    error!(
                        "Unknown type code {} found while reading the main header",
                        entry_type
                    );
                    self.kdbx_file.main_header.unknown_data =
                        (entry_type, self.read_header_field()?);
                }
            }
        }
        // Keep the end position of the header data
        self.header_data_end_position = self.reader.stream_position()?;
        Ok(())
    }

    fn read_header_field(&mut self) -> Result<Vec<u8>> {
        let mut buf = [0; 4];
        self.reader.read_exact(&mut buf).unwrap();
        let size = u32::from_le_bytes(buf);
        let mut buffer = Vec::new();
        let r = self.reader.by_ref();
        r.take(size as u64).read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn verify_stored_hash(&mut self) -> Result<()> {
        //Following header data we can find the hash data
        let mut stored_hash = [0; 32];
        self.reader.read_exact(&mut stored_hash).unwrap();
        //at this point, the stream is 32 bytes after the header data

        let header_data = read_stream_data(
            self.reader,
            self.header_data_start_position,
            self.header_data_end_position,
        )?;
        let cal_hash = crypto::sha256_hash_from_slice_vecs(&[&header_data])?;
        if cal_hash.to_vec() != stored_hash {
            return Err(Error::HeaderHashCheckFailed);
        }
        Ok(())
    }

    fn verify_header_hmac(&mut self) -> Result<()> {
        let mut stored_hmac_hash = [0; 32];
        self.reader.read_exact(&mut stored_hmac_hash)?;

        let header_data = read_stream_data(
            self.reader,
            self.header_data_start_position,
            self.header_data_end_position,
        )?;
        let r = crypto::verify_hmac_sha256(
            self.kdbx_file.hmac_key(),
            &[&header_data],
            &stored_hmac_hash,
        )?;

        if r {
            Ok(())
        } else {
            Err(Error::HeaderHmacHashCheckFailed)
        }
    }

    // Reads the encrypted payload content of the database that comes after header info and verifies
    // after extracting hmac blocks and the verification of each block of ecrypted data.
    // Returns the encrypted data blocks combined as the final payload.
    fn read_hmac_data_blocks(&mut self) -> Result<Vec<u8>> {
        let mut acc: Vec<u8> = Vec::new();
        // block index is a 64 bit number and used in block hmac key
        let mut blk_idx = 0u64;
        loop {
            // Extract the hmac hash that is stored in the begining of a block data
            let mut stored_blk_hmac_hash = [0; 32];
            self.reader.read_exact(&mut stored_blk_hmac_hash)?;

            // Next 4 bytes are the size of the actual encrypted block
            // The u32 value formed from these 4 bytes gives the block size in bytes count
            let mut size_buffer = [0; 4];
            self.reader.read_exact(&mut size_buffer)?;
            let blk_size = u32::from_le_bytes(size_buffer);

            if blk_size == 0 {
                // No more blocks
                break;
            }

            // Block data
            let mut data_buffer = Vec::new();
            self.reader
                .by_ref()
                .take(blk_size as u64)
                .read_to_end(&mut data_buffer)?;

            // Each Block's hmac key is based on the block index (LE number) which is a 64 bit number
            // and the previously computed hmac_part_key
            let blk_idx_bytes = blk_idx.to_le_bytes();
            let block_key = crypto::sha512_hash_from_slice_vecs(&[
                &blk_idx_bytes.to_vec(),
                self.kdbx_file.hmac_part_key(),
            ])?;

            // Verify the stored block hmac to the calculated one
            // The data for hmac calc is blk_index + blk_size + blk_data
            // All are in little endian bytes
            let r = crypto::verify_hmac_sha256(
                &block_key,
                &[&blk_idx_bytes, &size_buffer, &data_buffer],
                &stored_blk_hmac_hash,
            )?;
            if !r {
                return Err(Error::BlockHashCheckFailed);
            }
            // Accumulate the verified blocks of data
            acc.append(&mut data_buffer);
            // Next block
            blk_idx += 1;
        }

        Ok(acc)
    }

    fn decrypt_data(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ContentCipher::try_from(
            &self.kdbx_file.main_header.cipher_id,
            &self.kdbx_file.main_header.encryption_iv,
        )?;

        let start = std::time::Instant::now();
        let mut payload = cipher.decrypt(&encrypted_data, self.kdbx_file.master_key())?;
        debug!(
            "Decryption of data with size {} and elapsed time is  {} seconds  ",
            payload.len(),
            start.elapsed().as_secs()
        );

        if self.kdbx_file.main_header.compression_flag == 1 {
            let start = std::time::Instant::now();
            payload = util::decompress(&payload[..])?;
            debug!(
                "Uncompressing data with size {} and elapsed time {} seconds ",
                payload.len(),
                start.elapsed().as_secs()
            );
        };

        Ok(payload)
    }

    // Splits the inner header and the actual xml content bytes
    // Inner header data includes the binary data of any attchments
    fn split_inner_header_xml_content(&mut self, decrypted_data: &[u8]) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::<u8>::new());
        buf.write(decrypted_data)?;
        buf.seek(SeekFrom::Start(0))?;
        let mut hd_t = [0u8; 1];
        loop {
            // Read one byte that represents the inner header type
            buf.read_exact(&mut hd_t)?;

            // Read next 4 LE bytes that represent how many bytes to read for the data
            let mut size_buf = [0u8; 4];
            buf.read_exact(&mut size_buf)?;
            let bytes_to_read = u32::from_le_bytes(size_buf);

            // Next read the data based on bytes_to_read calculated
            let mut bytes_buf = Vec::new();
            if bytes_to_read != 0 {
                Read::by_ref(&mut buf)
                    .take(bytes_to_read as u64)
                    .read_to_end(&mut bytes_buf)?;
            }

            match hd_t[0] {
                inner_header_type::END_OF_HEADER => {
                    break;
                }
                inner_header_type::STREAM_ID => {
                    self.kdbx_file.inner_header.stream_cipher_id = util::to_u32(&bytes_buf)?;
                    //TODO: Verify that stream_cipher_id is for CHACHA20 only
                }
                inner_header_type::STREAM_KEY => {
                    self.kdbx_file.inner_header.inner_stream_key = bytes_buf;
                }
                inner_header_type::BINARY => {
                    // All entries attachments are stored as BINARY data
                    self.kdbx_file.inner_header.add_binary_data(bytes_buf);
                }
                // Should not come here?
                _ => {
                    return Err(Error::DataError("Unknown inner header type is found"));
                }
            }
        }
        let mut remaining_bytes: Vec<u8> = Vec::new();
        buf.read_to_end(&mut remaining_bytes)?;
        // remaining_bytes are the xml content as bytes data
        Ok(remaining_bytes)
    }

    fn read_xml_content(&mut self, xml_bytes: &[u8]) -> Result<()> {
        // TODO:
        // Following are used for any debugging to see the XML content during development.
        // This should be removed after making some command line program
        // Need to introduce cargo 'feature' to do this automatically on demand during dev test time

        /*
         // Dumps the raw xml content that has been decrypted
         let dump_xml_file_name = temp_raw_xml_dump_file_name("test_read.xml");
         super::write_xml_to_file(&dump_xml_file_name,xml_bytes).unwrap();
         println!("Wrote the raw xml to the file {}",&dump_xml_file_name);
        */

        //println!("xml: {}", std::str::from_utf8(xml_bytes).expect("utf conversion failed"));

        let cipher = ProtectedContentStreamCipher::try_from(
            self.kdbx_file.inner_header.stream_cipher_id,
            &self.kdbx_file.inner_header.inner_stream_key,
        )?;

        let mut r = xml_parse::parse(xml_bytes, Some(cipher))?;

        // IMPORTANT:We need to set attachment hashes in all entries read from xml
        r.after_xml_reading(
            self.kdbx_file
                .inner_header
                .entry_attachments
                .attachments_index_ref_to_hash(),
        );
        self.kdbx_file.keepass_main_content = Some(r);
        Ok(())
    }
}

#[allow(dead_code)]
fn temp_raw_xml_dump_file_name(name: &str) -> String {
    let mut path = std::env::temp_dir();
    //println!("The current directory is {}", path.display());
    path.push(name);
    //println!("The current directory is {}", path.display());
    path.to_str().unwrap().into()
}

/////

fn read_stream_data<R: Read + Seek>(reader: &mut R, start: u64, end: u64) -> Result<Vec<u8>> {
    let current_reader_position = reader.stream_position()?;

    //Sets the offset to the provided number of bytes from start
    reader.seek(SeekFrom::Start(start))?;
    let size = end - start;
    let mut buffer = Vec::new();

    //Creates a "by reference" adaptor for this instance of Read.
    //The returned adaptor also implements Read and will simply borrow this current reader
    //self.reader.take(...) will not work as that requires move of Reader
    reader.by_ref().take(size as u64).read_to_end(&mut buffer)?;

    // Resets the stream's position to its original position
    reader.seek(SeekFrom::Start(current_reader_position))?;

    Ok(buffer)
}

pub struct KdbxFileWriter<'a, W>
where
    W: Read + Write + Seek,
{
    writer: &'a mut W,
    // kdbx_file needs to be mutable as keys of KdbxFile etc are recomputed before writing
    kdbx_file: &'a mut KdbxFile,
}

impl<'a, W: Read + Write + Seek> KdbxFileWriter<'a, W> {
    pub(crate) fn new(writer: &'a mut W, kdbx_file: &'a mut KdbxFile) -> KdbxFileWriter<'a, W> {
        KdbxFileWriter { writer, kdbx_file }
    }

    pub(crate) fn write(&mut self) -> Result<()> {
        // IMPORATNT:
        // we need to recompute the keys for encryption so that any changes
        // in main header fields (seed, iv, cipher id etc) or credential changes
        // are taken care of. Even if there are no changes to the above mentioned variables,
        // we need to reset the seed and iv for every save
        self.kdbx_file.compute_all_keys(true)?;

        // kdbx file signature
        self.write_file_signature()?;

        // Main header
        self.kdbx_file.main_header.write_bytes(&mut self.writer)?;
        self.write_header_hash()?;

        // The main content of database
        let mut buf = self.write_compressed_encrypted_payload()?;
        self.write_hmac_data_blocks(&mut buf)?;

        self.writer.flush()?;

        Ok(())
    }

    fn write_file_signature(&mut self) -> Result<()> {
        self.writer.write(&constants::SIG1.to_le_bytes())?;
        self.writer.write(&constants::SIG2.to_le_bytes())?;
        self.writer.write(&constants::VERSION_41.to_le_bytes())?;
        Ok(())
    }

    fn write_header_hash(&mut self) -> Result<()> {
        let header_end = self.writer.stream_position()?;
        let header_data = read_stream_data(&mut self.writer, 0, header_end)?;
        let cal_hash = crypto::sha256_hash_from_slice_vecs(&[&header_data])?;
        self.writer.write(&cal_hash)?;

        let header_hmac_hash =
            crypto::hmac_sha256_from_slices(self.kdbx_file.hmac_key(), &[&header_data])?;
        self.writer.write(&header_hmac_hash)?;

        Ok(())
    }

    fn write_compressed_encrypted_payload(&mut self) -> Result<Vec<u8>> {
        let mut buf = Cursor::new(Vec::<u8>::new());

        if let Some(kp) = &mut self.kdbx_file.keepass_main_content {
            // Collect the attachment hash values from all entries and their history entries in an order
            let hashes = kp.root.get_attachment_hashes();

            // Write attachment binaries identified by the hashes to inner header
            self.kdbx_file
                .inner_header
                .write_all_bytes(hashes, &mut buf)?;

            // Need to set the new index_refs of all attachments after writing the binaries to inner header
            // so that this index is used in Ref attribute of Value tag
            // See root.set_attachment_index_refs -> entry.set_attachment_index_refs
            kp.before_xml_writing(
                self.kdbx_file
                    .inner_header
                    .entry_attachments
                    .attachment_hash_to_index_ref(),
            );

            // Need to get the stream cipher algorithm used to encrypt the fields with Protect = True
            // while creating the XML content
            let cipher = ProtectedContentStreamCipher::try_from(
                self.kdbx_file.inner_header.stream_cipher_id,
                &self.kdbx_file.inner_header.inner_stream_key,
            )?;

            debug!("Creating xml content start");
            let v = xml_parse::write_xml(kp, Some(cipher))?;
            debug!("Creating xml content completed");

            // Need to use {} and not the debug one {:?} to avoid \" in the print
            // println!("In db writing: XML content is \n {}", std::str::from_utf8(&v).unwrap());

            buf.write(&v)?;
        }

        let start = std::time::Instant::now();
        let v = buf.into_inner();
        debug!("Compressing started for data with  size {} ", v.len());
        let mut payload = if self.kdbx_file.main_header.compression_flag == 1 {
            util::compress(&v)?
        } else {
            v
        };
        debug!(
            "Compressing data with size {} and the elapsed time is {} seconds  ",
            payload.len(),
            start.elapsed().as_secs()
        );

        // Payload encryption
        let cipher = ContentCipher::try_from(
            &self.kdbx_file.main_header.cipher_id,
            &self.kdbx_file.main_header.encryption_iv,
        )?;

        // Incoming payload is not yet encrypted
        let start = std::time::Instant::now();
        payload = cipher.encrypt(&payload, self.kdbx_file.master_key())?;
        debug!(
            "Encryption of data elapsed time {} seconds ",
            start.elapsed().as_secs()
        );

        // Returns the encrypted payload
        Ok(payload)
    }

    // Complement to read_hmac_data_blocks that is carried out while reading the database main content
    fn write_hmac_data_blocks(&mut self, payload_data: &[u8]) -> Result<()> {
        let mut payload_data_buf = Cursor::new(Vec::<u8>::new());
        payload_data_buf.write(payload_data)?;
        payload_data_buf.seek(SeekFrom::End(0))?;
        let mut remaining_bytes = payload_data_buf.stream_position()?;

        let mut blk_idx = 0u64;
        let mut blk_size = cmp::min(PAYLOAD_BLOCK_SIZE, remaining_bytes);
        payload_data_buf.seek(SeekFrom::Start(0))?;
        loop {
            // Read a Block size data from payload_data_buf
            let mut data_buffer = Vec::new();
            let data_read = Read::by_ref(&mut payload_data_buf)
                .take(blk_size)
                .read_to_end(&mut data_buffer)?;

            // Find HMAC of this block
            // block hmac key is based on block index (LE number) which is a 64 bit number and previously
            // computed hmac part key
            let blk_idx_bytes = blk_idx.to_le_bytes();
            let block_key = crypto::sha512_hash_from_slice_vecs(&[
                &blk_idx_bytes.to_vec(),
                self.kdbx_file.hmac_part_key(),
            ])?;

            let blk_size_in_bytes = (data_read as u32).to_le_bytes();
            let blk_hmac_hash = crypto::hmac_sha256_from_slices(
                &block_key,
                &[&blk_idx_bytes, &blk_size_in_bytes, &data_buffer],
            )?;

            // Write the hmac hash
            self.writer.write(&blk_hmac_hash)?;

            // Calculate LE 4 bytes of the size of the actual encrypted block
            // And Write the blk size
            self.writer.write(&blk_size_in_bytes)?;

            if blk_size == 0 {
                break;
            }
            // Write the data_buffer of blk_size data (Block data)
            self.writer.write(&data_buffer)?;

            remaining_bytes = remaining_bytes - blk_size;
            blk_size = cmp::min(PAYLOAD_BLOCK_SIZE, remaining_bytes);

            // Next block
            blk_idx += 1;
        }
        Ok(())
    }
}
