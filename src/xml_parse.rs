use quick_xml::escape::{self, unescape};
use quick_xml::events::attributes::{Attribute, Attributes};
use quick_xml::events::Event;
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText};
use quick_xml::name::QName;
use quick_xml::Reader as QuickXmlReader;
use quick_xml::Writer as QuickXmlWriter;

use std::collections::HashMap;
use std::io::Cursor;
use std::io::{BufRead, Write};

use crate::constants::key_file_xml_element::*;
use crate::constants::xml_element::*;
use crate::constants::GENERATOR_NAME;
use crate::crypto::ProtectedContentStreamCipher;
use crate::db::KeyFileData;
use crate::db_content::*;
use crate::error::{Error, Result};
use crate::util;
use log::{debug, error, info};

pub struct XmlReader<'a> {
    reader: QuickXmlReader<&'a [u8]>,
    stream_cipher: Option<ProtectedContentStreamCipher>,
}

// Macro called for reading specific set of inner tags

macro_rules! read_tags {
    ($self:ident, start_tag_fns {$($start_tag:tt => $start_tag_action:tt),* },
        start_tag_blks {$($parent_tag:tt => $parent_tag_action:tt),*},
        empty_tags {$($empty_tag:pat => $empty_tag_action:tt),*} , $end_tag:expr   )
        => {
        let mut buf:Vec<u8> = vec![];
        loop {

            match $self.reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        $($start_tag => {
                            let content = $self.reader.read_text(QName($start_tag))?;
                            $start_tag_action(content.to_string(),&mut e.attributes(),&mut $self.stream_cipher);
                        }
                        )*

                        $($parent_tag  => {
                            // parent_tag_action is a block intead of a closure so that we can use "self" methods
                            // But if we need to access the attributes of this $parent_tag we need to pass a variable name as
                            // "tt" in "$attributes" and then can be set with value of e.attributes() and
                            // can be used inside parent_tag_action block
                            // start_tag_blks {$($attributes:tt,$parent_tag:tt => $parent_tag_action:tt),*},
                            // let mut $attributes = e.attributes();
                            // let mut $attributes = e.attributes().by_ref().filter_map(|a| a.ok()).collect::<Vec<_>>();
                            $parent_tag_action
                        })*

                        x => {
                            // Just consume/skip any other tags that are not listed above
                            let t = std::str::from_utf8(&x)?;
                            let et = std::str::from_utf8($end_tag);
                            debug!("No matching action found and skipping the tag: {} and end tag is {:?}", &t, &et);
                            skip_tag(x, &mut $self.reader)?;
                        }
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    match e.name().as_ref() {
                        $($empty_tag => {
                            $empty_tag_action(&mut e.attributes())
                        }
                        )*
                        x => {
                            if let Ok(et) = std::str::from_utf8(x) {
                                debug!("The attribute handling action is not used for the Empty tag: {}",et);
                            }
                            ()
                        }
                    }
                }

                Ok(Event::End(ref e)) if e.name().as_ref() == $end_tag => {
                    break;
                }
                Ok(Event::End(ref e)) if e.name().as_ref() != $end_tag => {
                    let ep = std::str::from_utf8($end_tag);
                    return Err(Error::XmlReadingFailed(format!("Found unexpected end tag {:?} when only expected end tag is {:?}",e,ep)));
                }
                Ok(Event::Eof) => {
                    let ep = std::str::from_utf8($end_tag);
                    return Err(Error::XmlReadingFailed(format!("Reached end before seeing the end tag {:?}", ep)));
                }
                Ok(ref x) => {
                    //TODO: Log any other events for debugging
                    let ep = std::str::from_utf8($end_tag);
                    println!("Unhandled event {:?} before seeing the end tag {:?}", x,ep);
                }
                Err(e) => {
                    return Err(Error::from(e));
                }
            }
        }
    };
}

fn skip_tag<B: BufRead>(tag: &[u8], reader: &mut QuickXmlReader<B>) -> Result<()> {
    let mut buf = vec![];
    reader.read_to_end_into(QName(tag), &mut buf)?;
    Ok(())
}

// Need to unescape the previously escaped `content` and replaces all xml
// escaped characters (`&...;`) into their corresponding value.
// quick_xml escapes any text content while writing and here we are doing reverse unescape
// "   &quot;
// '   &apos;
// <   &lt;
// >   &gt;
// &   &amp;
// See https://stackoverflow.com/questions/1091945/what-characters-do-i-need-to-escape-in-xml-documents
// https://docs.rs/quick-xml/0.30.0/quick_xml/escape/fn.escape.html
// https://docs.rs/quick-xml/0.30.0/quick_xml/events/struct.BytesText.html#method.new (escapes text content in this call)
fn content_unescape(content: &str) -> String {
    match unescape(&content) {
        Ok(unescaped_content) => unescaped_content.to_string(),
        Err(e) => {
            error!("XML read time content unescaping failed with error {} ; Returning the original content", e);
            content.to_string()
        }
    }
}

#[inline]
fn content_to_int(content: String) -> i32 {
    if let Ok(i) = content.parse::<i32>() {
        i
    } else {
        // TODO accept some default value and return in case of parsing failure
        error!(
            "Parsing of content {} as i32 failed and returning -1",
            content
        );
        -1
    }
}

#[inline]
fn content_to_bool(content: String) -> bool {
    if content.to_lowercase() == "true" {
        true
    } else {
        false
    }
}

#[inline]
fn content_to_dt(content: String) -> chrono::NaiveDateTime {
    if let Some(d) = util::decode_datetime_b64(&content) {
        d
    } else {
        error!(
            "Parsing of content {} to date failed and returning now",
            content
        );
        util::now_utc()
    }
}

#[inline]
fn content_to_uuid(content: &String) -> uuid::Uuid {
    match util::decode_uuid(content) {
        Some(u) => u,
        None => uuid::Uuid::default(), //TODO: Log the uuid conversion error
    }
}

#[inline]
fn content_to_string_opt(content: String) -> Option<String> {
    if content.trim().is_empty() {
        None
    } else {
        Some(content)
    }
}

#[inline]
fn bool_to_xml_bool(flag: bool) -> String {
    if flag {
        "True".into()
    } else {
        "False".into()
    }
}

impl<'a> XmlReader<'a> {
    pub fn new(data: &[u8], cipher: Option<ProtectedContentStreamCipher>) -> XmlReader {
        let mut qxmlreader = QuickXmlReader::from_reader(data);
        qxmlreader.trim_text(true);
        XmlReader {
            reader: qxmlreader,
            stream_cipher: cipher,
        }
    }

    pub fn parse(&mut self) -> Result<KeepassFile> {
        log::trace!("Going to parse read the the xml  ...");
        let mut kp = KeepassFile::new();
        let mut buf: Vec<u8> = vec![];
        let mut xml_decl_available = false;
        loop {
            match self.reader.read_event_into(&mut buf) {
                Ok(Event::Decl(ref _e)) => {
                    xml_decl_available = true;
                }
                Ok(Event::DocType(_)) => {}
                Ok(Event::PI(_)) => {}
                Ok(Event::Text(_)) => {}
                Ok(Event::Start(ref e)) => {
                    if !xml_decl_available {
                        return Err(Error::XmlReadingFailed(format!(
                            "Xml content does not have XML decl"
                        )));
                    }
                    match e.name().as_ref() {
                        KEEPASS_FILE => {
                            let r = self.read_top_level()?;
                            kp.meta = r.0;
                            kp.root = r.1;
                        }
                        x => {
                            //debug!("MAIN: in match {:?}", std::str::from_utf8(e.name()).unwrap());
                            //debug!("MAIN: in match {:?} KEEPASS_FILE", std::str::from_utf8(KEEPASS_FILE).unwrap());
                            return Err(Error::XmlReadingFailed(format!(
                                "Unexpected starting tag {:?}",
                                std::str::from_utf8(x)
                            )));
                        }
                    }
                }
                Ok(Event::Empty(ref _e)) => {}
                Ok(Event::End(ref e)) => {
                    // KeePassFile end tag should have been consumed in read_top_level
                    info!("PARSE:End of tag {:?}", e.name());
                }

                Ok(Event::CData(ref _e)) => {}

                Ok(Event::Comment(ref _e)) => {}

                Ok(Event::Eof) => {
                    //debug!("MAIN: End of File");
                    break;
                }

                Err(e) => {
                    debug!("XML content reading error {:?}", e);
                    return Err(Error::from(e));
                }
            }
        }
        Ok(kp)
    }

    fn read_top_level(&mut self) -> Result<(Meta, Root)> {
        let mut meta = Meta::new();
        let mut root = Root::new();

        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                META => {
                    self.read_meta(&mut meta)?;
                },
                ROOT => {
                    self.read_root(&mut root)?;
                }
            },
            empty_tags {},
            KEEPASS_FILE);

        Ok((meta, root))
    }

    fn read_meta(&mut self, meta: &mut Meta) -> Result<()> {
        read_tags! (
            self,
            start_tag_fns {
                GENERATOR => (
                    |content:String, _,  _| meta.generator = content
                ),
                DATABASE_NAME => (
                    |content:String, _,  _| meta.database_name = content
                ),
                DATABASE_DESCRIPTION => (
                    |content:String, _,  _| meta.database_description = content
                ),
                LAST_SELECTED_GROUP => (
                    |content:String, _,  _| meta.last_selected_group = content_to_uuid(&content)
                ),
                HISTORY_MAX_ITEMS => (
                    |content:String, _,  _| meta.meta_share.set_history_max_items(content_to_int(content))
                ),
                HISTORY_MAX_SIZE => (
                    |content:String, _,  _| meta.meta_share.set_history_max_size(content_to_int(content))
                ),
                MAINTENANCE_HISTORY_DAYS=> (
                    |content:String, _,  _| meta.maintenance_history_days = content_to_int(content)
                ),
                RECYCLE_BIN_ENABLED => (
                    |content:String, _,  _| meta.recycle_bin_enabled = content_to_bool(content)
                ),
                RECYCLE_BIN_UUID => (
                    |content:String, _,  _| meta.recycle_bin_uuid = content_to_uuid(&content)
                ),
                DATABASE_NAME_CHANGED => (
                    |content:String, _,  _|  meta.database_name_changed = content_to_dt(content)
                ),
                SETTINGS_CHANGED => (
                    |content:String, _,  _| meta.settings_changed = content_to_dt(content)
                )

            },
            start_tag_blks {
                //attributes1,
                MEMORY_PROTECTION => {
                    self.read_memory_protection(&mut meta.memory_protection)?;
                    //debug!("Attributes of  MEMORY_PROTECTION will be {:?}",attributes1);
                },
                //attributes2,
                CUSTOM_ICONS => {
                    //debug!("Called CUSTOM_ICONS");
                    self.read_custom_icons(&mut meta.custom_icons)?;
                    //debug!("CUSTOM_ICONS Content will be {:?}",attributes2);
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut meta.custom_data)?;
                }
            },
            empty_tags {},
            META
        );
        Ok(())
    }

    fn read_memory_protection(&mut self, mp: &mut MemoryProtection) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                PROTECT_PASSWORD =>
                (|content:String, _,  _|
                    mp.protect_password = content_to_bool(content)
                ),
                PROTECT_NOTES =>
                (|content:String, _,  _|
                    mp.protect_notes = content_to_bool(content)
                ),
                PROTECT_TITLE =>
                (|content:String, _,  _|
                    mp.protect_title = content_to_bool(content)
                )
            },
            start_tag_blks {},
            empty_tags {},
            MEMORY_PROTECTION
        );
        Ok(())
    }

    fn read_custom_icons(&mut self, custom_icons: &mut CustomIcons) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ICON => {
                    custom_icons.icons.push(self.read_custom_icon()?);
                }
            },
            empty_tags{},
            CUSTOM_ICONS
        );
        Ok(())
    }

    fn read_custom_icon(&mut self) -> Result<Icon> {
        let mut icon = Icon::default();
        read_tags!(self,
            start_tag_fns {
                UUID => (|content:String, _,  _| icon.uuid = content_to_uuid(&content)),
                DATA => (|content:String, _,  _| {
                    if let Some(d) = util::base64_decode(&content).ok() {
                        icon.data = d;
                    }
                }),
                NAME => (|content:String, _,  _|  icon.name = Some(content))

            },
            start_tag_blks {},
            empty_tags{},
            ICON
        );

        Ok(icon)
    }

    fn read_custom_data(&mut self, custom_data: &mut CustomData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ITEM => {
                    custom_data.insert_item(self.read_custom_data_item()?);
                }
            },
            empty_tags{},
            CUSTOM_DATA);
        Ok(())
    }

    fn read_custom_data_item(&mut self) -> Result<Item> {
        let mut item = Item::default();
        read_tags!(self,
            start_tag_fns {
                KEY =>
                (|content:String, _,  _|
                    item.key = content
                ),
                VALUE =>
                (|content:String, _,  _|
                    item.value = content
                ),
                LAST_MODIFICATION_TIME =>
                (|content:String, _,  _|
                    item.last_modification_time = if !content.trim().is_empty() {
                            Some(content_to_dt(content))
                        }
                        else {
                            None
                        }
                )
            },
            start_tag_blks {},
            empty_tags{},
            ITEM
        );
        Ok(item)
    }

    fn read_root(&mut self, root: &mut Root) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                GROUP => {
                    root.root_uuid = self.read_group(None,&mut root.all_groups,&mut root.all_entries)?;
                }
            },
            empty_tags {},
            ROOT
        );
        Ok(())
    }

    fn read_group(
        &mut self,
        parent_group_uuid: Option<uuid::Uuid>,
        all_groups: &mut HashMap<uuid::Uuid, Group>,
        all_entries: &mut HashMap<uuid::Uuid, Entry>,
    ) -> Result<uuid::Uuid> {
        let mut group = Group::new();
        // All non root groups will have some parent group as parent
        if let Some(gid) = parent_group_uuid {
            group.parent_group_uuid = gid;
        }
        read_tags!(self,
            start_tag_fns {
                NAME => (|content:String, _,  _| group.name = content),
                UUID => (|content:String, _,  _| group.uuid = content_to_uuid(&content)),
                ICON_ID => (|content:String, _,  _| group.icon_id = content_to_int(content)),
                LAST_TOP_VISIBLE_ENTRY => (|content:String, _,  _| group.last_top_visible_group = content_to_uuid(&content)),
                IS_EXPANDED => (|content:String, _,  _| group.is_expanded = content_to_bool(content)),
                NOTES => (|content:String, _,  _| group.notes = content_unescape(&content)),
                TAGS => (|content:String, _,  _| group.tags = content),
                ENABLE_AUTO_TYPE => (|content:String, _,  _| {
                    if content.trim().to_lowercase() == "null" {
                        group.enable_auto_type = None
                    } else {
                        group.enable_auto_type = Some(content_to_bool(content))
                    }
                })
            },
            start_tag_blks {
                TIMES => {
                    self.read_times(&mut group.times)?;
                },
                GROUP => {
                    //group.groups.push(self.read_group()?);
                    group.group_uuids.push(self.read_group(Some(group.uuid),all_groups,all_entries)?);
                },
                ENTRY => {
                    // group.entries.push(self.read_entry()?);
                    // It is assumed that Entry tag of a group is seen after UUID tag of Group so group.uuid should have valid uuid. See next comment
                    // TODO:
                    // If entry tag of a group comes before UUID tag of Group, then group.uuid will be a Uuid:Default vlaue.
                    // May need to fix when that happens with other KeePass app generated xml content.
                    // So far a group's entry always come after the group's uuid read
                    group.entry_uuids.push(self.read_entry(group.uuid, all_entries)?);
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut group.custom_data)?;
                }
            },
            empty_tags {},
            GROUP
        );
        // TODO: We may need to ensure all Entries of this group has its group_uuid is set to this group's UUID. See above comments in 'ENTRY'
        let gid = group.uuid; // copy to return
        all_groups.insert(group.uuid, group);
        Ok(gid)
    }

    fn read_entry_data(&mut self) -> Result<Entry> {
        let mut entry = Entry::new();
        read_tags!(self,
            start_tag_fns {
                UUID => (|content:String, _,  _| entry.uuid = content_to_uuid(&content)),
                ICON_ID => (|content:String, _,  _| entry.icon_id = content_to_int(content)),
                TAGS => (|content:String, _,  _| entry.tags = content)
            },
            start_tag_blks {
                TIMES => {
                    self.read_times(&mut entry.times)?;
                },
                STRING => {
                    entry.entry_field.insert_key_value(self.read_key_value()?);
                },
                BINARY => {
                    entry.binary_key_values.push(self.read_binary_key_value()?);
                },
                HISTORY => {
                    entry.history = self.read_histrory()?;
                },
                CUSTOM_DATA => {
                    self.read_custom_data(&mut entry.custom_data)?;
                },
                AUTO_TYPE => {
                    entry.auto_type = self.read_auto_type()?;
                }
            },
            empty_tags {},
            ENTRY
        );

        Ok(entry)
    }

    fn read_entry(
        &mut self,
        group_uuid: uuid::Uuid,
        all_entries: &mut HashMap<uuid::Uuid, Entry>,
    ) -> Result<uuid::Uuid> {
        let mut entry = self.read_entry_data()?; //Entry::new();
        entry.group_uuid = group_uuid;
        let eid = entry.uuid;
        all_entries.insert(entry.uuid, entry);
        Ok(eid)
    }

    /// Reads the "History" tag content. Each "History" tag has 0 or more Entries
    /// The Entry tag under History should not contain any History tag
    fn read_histrory(&mut self) -> Result<History> {
        let mut history = History::default();
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                ENTRY => {
                    history.entries.push(self.read_entry_data()?);
                }
            },
            empty_tags {},
            HISTORY
        );
        Ok(history)
    }

    fn read_binary_key_value(&mut self) -> Result<BinaryKeyValue> {
        let mut kv = BinaryKeyValue::default();
        read_tags!(self,
            start_tag_fns {
                KEY =>(|content:String, _,  _| kv.key = content),
                // This handles the tag where we have both start and end tag like <Value Ref="0"></Value>
                VALUE => (|_, attributes:&mut Attributes,  _| kv.index_ref = attachment_ref_index(attributes))
            },
            start_tag_blks {},
            empty_tags {
                // This handles the tag where we have only an empty tag with attributes like <Value Ref="0" />
                VALUE =>
                (|attributes:&mut Attributes| {
                    kv.index_ref = attachment_ref_index(attributes);
                    }
                )
            },
            BINARY
        );
        Ok(kv)
    }

    fn read_key_value(&mut self) -> Result<KeyValue> {
        let mut kv = KeyValue::new();
        read_tags!(self,
            start_tag_fns {
                KEY =>
                (|content:String, _attributes, _cipher| {
                    // Xml tag 'Key' may have a text content with escaped charaters that are to be unescaped
                    kv.key = content_unescape(&content);
                }),
                VALUE =>
                (|content:String, attributes:&mut Attributes, cipher:&mut Option<ProtectedContentStreamCipher>| {
                        // Xml tag 'Value' may have a text content with escaped charaters that are to be unescaped
                        //println!("KV:Value content is {}",&content);

                        kv.protected = is_value_protected(attributes);
                        //debug!("Key Value content is key:{}, value:{},protected:{}",&kv.key,&content,&kv.protected);
                        if kv.protected {
                            // Will there be a situation where field is protected and no cipher is used?
                            if let Some(ref mut cip) = cipher {
                                if let Ok(v) = cip.process_basic64_str(&content) {
                                    kv.value = v;
                                }
                            } else {
                                kv.value = content_unescape(&content);
                            }
                        }
                        else {
                                kv.value = content_unescape(&content);
                        }
                    }
                )
            },
            start_tag_blks {},
            // empty_tags {},
            empty_tags {
                // This handles the tag where we have only an empty tag with attributes like <Value Protected="True"/>
                VALUE =>
                (|attributes:&mut Attributes| {
                    kv.protected = is_value_protected(attributes);
                    }
                )
            },
            STRING
        );
        //debug!("Key value after reading is {:?}",&kv);
        Ok(kv)
    }

    /// Reads the "AutoType" tag content. Each "AutoType" tag has 0 or more Association
    fn read_auto_type(&mut self) -> Result<AutoType> {
        let mut auto_type = AutoType::default();
        read_tags!(self,
            start_tag_fns {
                ENABLED =>
                (|content:String, _attributes, _cipher| {
                    auto_type.enabled = content_to_bool(content);
                }),
                DEFAULT_SEQUENCE => (|content:String, _attributes, _cipher| {
                    auto_type.default_sequence = content_to_string_opt(content);
                })
            },
            start_tag_blks {
                ASSOCIATION => {
                    auto_type.associations.push(self.read_auto_type_association()?);
                }
            },
            empty_tags {},
            AUTO_TYPE
        );
        Ok(auto_type)
    }

    fn read_auto_type_association(&mut self) -> Result<Association> {
        let mut association = Association::default();
        read_tags!(self,
            start_tag_fns {
                WINDOW =>
                (|content:String, _attributes, _cipher|
                    association.window = content),

                KEY_STROKE_SEQUENCE =>
                (|content:String, _, _|
                    association.key_stroke_sequence = content_to_string_opt(content))
            },
            start_tag_blks {},
            empty_tags {},
            ASSOCIATION
        );
        Ok(association)
    }

    fn read_times(&mut self, times: &mut Times) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                EXPIRES => (
                    |content:String, _,  _|  times.expires= content_to_bool(content)
                ),
                EXPIRY_TIME => (
                    |content:String, _,  _|  times.expiry_time = content_to_dt(content)
                ),
                LAST_MODIFICATION_TIME => (
                    |content:String, _,  _|  times.last_modification_time = content_to_dt(content)
                ),
                CREATION_TIME => (
                    |content:String, _,  _|  times.creation_time = content_to_dt(content)
                ),
                LAST_ACCESS_TIME => (
                    |content:String, _,  _|  times.last_access_time = content_to_dt(content)
                ),
                LOCATION_CHANGED => (|content:String, _,  _|  times.location_changed = content_to_dt(content)),
                USAGE_COUNT => (|content:String, _,  _|  times.usage_count = content_to_int(content))

            },
            start_tag_blks {},
            empty_tags {},
            TIMES

        );

        Ok(())
    }
}

fn is_value_protected(attributes: &mut Attributes) -> bool {
    let mut protected = false;
    let mut v = attributes
        .by_ref()
        .filter_map(|a| a.ok())
        .collect::<Vec<_>>();
    // Expected at leaset one attribute or no attributes for the the tag <Value>
    // e.g <Value Protected="True">RcHUs0nSHfunhQA=</Value>
    if !v.is_empty() {
        match v.pop() {
            Some(Attribute {
                key: QName(b"Protected"),
                value: x,
            }) => {
                //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                if let std::borrow::Cow::Borrowed(a) = x {
                    //debug!("@@@@ a is {:?}",std::str::from_utf8(a).ok());
                    if b"True" == a {
                        protected = true;
                    }
                }
            }
            // Log as error if these happen when reading other KeePass app generated
            // xml. This may happen if such apps introduce app specific changes. So far we never saw these
            Some(x) => error!(
                "Some unexpected attribute {:?} for the protected value for String -> Value tag",
                x
            ),
            None => error!("No protected attribute for this Value tag - String -> Value tag"),
        }
    }
    protected
}

fn attachment_ref_index(attributes: &mut Attributes) -> i32 {
    let mut ref_index = -1;
    let mut v = attributes
        .by_ref()
        .filter_map(|a| a.ok())
        .collect::<Vec<_>>();
    // Expected at leaset one attribute for the the tag <Value>
    // e.g <Value Ref="0"/>
    if !v.is_empty() {
        match v.pop() {
            Some(Attribute {
                key: QName(b"Ref"),
                value: x,
            }) => {
                //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                if let std::borrow::Cow::Borrowed(a) = x {
                    //debug!("@@@@ a is {:?}",std::str::from_utf8(a).ok());
                    if let Some(i) = std::str::from_utf8(a).ok() {
                        if let Some(i) = i.parse::<i32>().ok() {
                            ref_index = i;
                        }
                    }
                }
            }
            Some(x) => error!(
                "Some unexpected attribute {:?} for the attachment Binary -> Value tag",
                x
            ),
            None => {
                error!("No attribute is for this Value tag of attachment - Binary -> Value tag")
            }
        }
    }
    ref_index
}

/// Start parsing incoming xml bytes content
pub fn parse(data: &[u8], cipher: Option<ProtectedContentStreamCipher>) -> Result<KeepassFile> {
    let mut reader = XmlReader::new(&data[..], cipher);
    let r = reader.parse();
    r
}

///////   All XML writing related //////////

macro_rules! write_tags {
    ($self:ident, $($tag_name:expr, $txt:expr),*) => {
        // Write empty tag if the content passed in $txt is a empty string
        // $txt should be evaluated once and reuse. Otherwise it will be evaluated
        // each time it is used
        $( let val = &$txt; // $txt evaluates to a String
            let name_of_tag  = std::str::from_utf8($tag_name)?;
            if val.is_empty() {
                $self.writer.write_event(Event::Empty(BytesStart::new(name_of_tag)))?;
            } else {
                $self.writer.write_event(Event::Start(BytesStart::new(name_of_tag)))?;
                // Creates a new BytesText from a string. The string is expected not to be escaped
                // quick_xml escapes the text content internally
                $self.writer.write_event(Event::Text(BytesText::new(val)))?;
                $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
            }
        )*
    };
}

macro_rules! write_parent_child_tags {
    ($self:ident, $parent_tag:expr, $($tag_name:expr, $txt:expr),*) => {
        let name_of_paren_tag  = std::str::from_utf8($parent_tag)?;
        $self.writer.write_event(Event::Start(BytesStart::new(name_of_paren_tag)))?;
        write_tags!($self, $($tag_name, $txt),*);
        $self.writer.write_event(Event::End(BytesEnd::new(name_of_paren_tag)))?;
    }
}

macro_rules! write_tags_with_attributes {
    ($self:ident, $($tag_name:expr, $attrs:expr,$txt:expr),*) => {
        $(
            let name_of_tag  = std::str::from_utf8($tag_name)?;
            let mut my_element = BytesStart::new(name_of_tag);
            for a in $attrs.iter() {
                my_element.push_attribute(*a);
            }
            let s:&str = $txt.as_ref();
            $self.writer.write_event(Event::Start(my_element))?;
            $self.writer.write_event(Event::Text(BytesText::new(s)))?; //&$txt
            $self.writer.write_event(Event::End(BytesEnd::new(name_of_tag)))?;
        )*
    };
}

macro_rules! write_parent_child_with_attributes {
    ($self:ident, $parent_tag:expr, $($tag_name:expr, $attrs:expr,$txt:expr),*) => {
        let name_of_paren_tag  = std::str::from_utf8($parent_tag)?;
        $self.writer.write_event(Event::Start(BytesStart::new(name_of_paren_tag)))?;
        write_tags_with_attributes!($self, $($tag_name, $attrs,$txt),*);
        $self.writer.write_event(Event::End(BytesEnd::new(name_of_paren_tag)))?;
    }
}

pub struct XmlWriter<W: Write> {
    writer: QuickXmlWriter<W>,
    //stream_cipher: ProtectedContentStreamCipher,
    stream_cipher: Option<ProtectedContentStreamCipher>,
}

impl<W: Write> XmlWriter<W> {
    pub fn new(writer: W, cipher: Option<ProtectedContentStreamCipher>) -> Self {
        Self {
            writer: QuickXmlWriter::new(writer),
            stream_cipher: cipher,
        }
    }

    pub fn new_with_indent(writer: W, cipher: Option<ProtectedContentStreamCipher>) -> Self {
        Self {
            writer: QuickXmlWriter::new_with_indent(writer, b" "[0], 2),
            stream_cipher: cipher,
        }
    }

    fn write_meta(&mut self, keepass_file: &KeepassFile) -> Result<()> {
        let meta_tag = std::str::from_utf8(META)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(meta_tag)))?;

        write_tags! { self,
            GENERATOR,GENERATOR_NAME, //keepass_file.meta.generator,
            DATABASE_NAME,keepass_file.meta.database_name,
            DATABASE_DESCRIPTION, keepass_file.meta.database_description,
            HISTORY_MAX_ITEMS,keepass_file.meta.meta_share.history_max_items().to_string(),
            HISTORY_MAX_SIZE,keepass_file.meta.meta_share.history_max_size().to_string(),
            MAINTENANCE_HISTORY_DAYS, keepass_file.meta.maintenance_history_days.to_string(),
            RECYCLE_BIN_ENABLED, if keepass_file.meta.recycle_bin_enabled {"True"} else {"False"},
            RECYCLE_BIN_UUID, util::encode_uuid(&keepass_file.meta.recycle_bin_uuid),
            SETTINGS_CHANGED, util::encode_datetime(&keepass_file.meta.settings_changed)
        };

        self.write_custom_data(&keepass_file.meta.custom_data)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(meta_tag)))?;

        Ok(())
    }

    fn write_times(&mut self, times: &Times) -> Result<()> {
        write_parent_child_tags! {
            self,
            TIMES,
            LAST_MODIFICATION_TIME, util::encode_datetime(&times.last_modification_time),
            CREATION_TIME, util::encode_datetime(&times.creation_time),
            LAST_ACCESS_TIME,util::encode_datetime(&times.last_access_time),
            EXPIRY_TIME, util::encode_datetime(&times.expiry_time),
            EXPIRES, if times.expires {"True"} else {"False"},
            USAGE_COUNT,times.usage_count.to_string()
        };

        Ok(())
    }

    fn write_custom_data(&mut self, custom_data: &CustomData) -> Result<()> {
        let custom_data_tag = std::str::from_utf8(CUSTOM_DATA)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(custom_data_tag)))?;

        for item in custom_data.get_items().iter() {
            // Need to evaluate 'last_modification_time' before passing it to the macro.
            // Otherwise this match will be evaluated twice - first time here
            // and again while executing the expanded code
            write_parent_child_tags! {
                self,
                ITEM,
                KEY, &item.key,
                VALUE, &item.value,
                LAST_MODIFICATION_TIME, match item.last_modification_time {
                    Some(ref d) => {
                        util::encode_datetime(d)
                    } ,
                    None => {
                        util::empty_str()}
                }
            };
        }

        self.writer
            .write_event(Event::End(BytesEnd::new(custom_data_tag)))?;

        Ok(())
    }

    fn write_group(
        &mut self,
        group_uuid: &uuid::Uuid,
        all_groups: &HashMap<uuid::Uuid, Group>,
        all_entries: &HashMap<uuid::Uuid, Entry>,
    ) -> Result<()> {
        let group_tag = std::str::from_utf8(GROUP)?;
        if let Some(group) = all_groups.get(group_uuid) {
            self.writer
                .write_event(Event::Start(BytesStart::new(group_tag)))?;
            write_tags! { self,
                NAME, group.name,
                UUID,util::encode_uuid(&group.uuid), //group.uuid.to_string(),
                ICON_ID,group.icon_id.to_string(),
                TAGS,group.tags,
                NOTES, group.notes,
                IS_EXPANDED, if group.is_expanded {"True"} else {"False"}
            };

            self.write_times(&group.times)?;

            //Custom Data
            self.write_custom_data(&group.custom_data)?;

            for e_uuid in group.entry_uuids.iter() {
                self.write_entry(e_uuid, all_entries, false)?;
            }

            for g_uuid in group.group_uuids.iter() {
                self.write_group(g_uuid, all_groups, all_entries)?;
            }

            self.writer
                .write_event(Event::End(BytesEnd::new(group_tag)))?;
        } else {
            return Err(Error::DataError(
                "Writing group failed as no value found in the lookup map",
            ));
        }

        Ok(())
    }

    // Writes the AutoType tag and its children
    fn write_entry_auto_type(&mut self, auto_type: &AutoType) -> Result<()> {
        let tag_element = std::str::from_utf8(AUTO_TYPE)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        write_tags! { self,
            ENABLED, bool_to_xml_bool(auto_type.enabled),
            DEFAULT_SEQUENCE,  auto_type.default_sequence.as_ref().map_or("", |s| s)
        };

        // Writes Association tag and its children
        for association in auto_type.associations.iter() {
            write_parent_child_tags! {
                self,
                ASSOCIATION,
                WINDOW, association.window,
                KEY_STROKE_SEQUENCE, association.key_stroke_sequence.as_ref().map_or("", |s| s)
            };
        }

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }

    fn write_entry_data(&mut self, entry: &Entry, in_history: bool) -> Result<()> {
        //let temp_title = entry.entry_field.find_key_value("Title");
        //debug!("Start of writing the entry with Title {:?}", temp_title);

        let tag_element = std::str::from_utf8(ENTRY)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        write_tags! { self,
            UUID, util::encode_uuid(&entry.uuid), //entry.uuid.to_string(),
            ICON_ID,entry.icon_id.to_string(),
            TAGS,entry.tags
        };

        // Times tag and the children
        self.write_times(&entry.times)?;

        // The String tag has childeren with attributes
        let empty_attr: Vec<(&str, &str)> = vec![];
        for s in entry.entry_field.get_key_values().iter() {
            //debug!("Writing kvs {:?}",s);

            let mut vp = vec![];
            // TODO: Need to find a better way to get the encrypted data
            // We need to create a temp var _e outside the 'if protected' block so that encrypted data can be used later.
            // Setting content = &self.stream_cipher.process_content_b64_str fails with error
            // "temporary value dropped while borrowed",
            // "creates a temporary which is freed while still in use"
            let mut _e = String::new();
            let mut content = &s.value;
            if s.protected {
                vp.push(("Protected", "True"));
                //IMPORTANT:
                // We should use stream cipher to encrypt only if content is not empty
                // Otherwise cipher call will return an error
                if !s.value.is_empty() {
                    if let Some(ref mut cipher) = &mut self.stream_cipher {
                        _e = cipher.process_content_b64_str(&s.value)?;
                        content = &_e;
                    }
                }
            }

            write_parent_child_with_attributes! {
                self,
                STRING,
                KEY, empty_attr, s.key,
                VALUE, vp, content
            };
        }
        // Binary tag for attachment where Value tag has an attribute
        for b in entry.binary_key_values.iter() {
            write_parent_child_with_attributes! {
                self,
                BINARY,
                KEY, empty_attr, b.key,
                VALUE, vec![("Ref", b.index_ref.to_string().as_str())],b.value
            };
        }
        // Entry's Custom Data
        self.write_custom_data(&entry.custom_data)?;

        self.write_entry_auto_type(&entry.auto_type)?;

        // We need to exclude the History tag while writing the child Entry tag that comes under the History tag
        if !in_history {
            let history_tag_element = std::str::from_utf8(HISTORY)?;
            self.writer
                .write_event(Event::Start(BytesStart::new(history_tag_element)))?;
            for e in entry.history.entries.iter() {
                self.write_entry_data(e, true)?;
            }
            self.writer
                .write_event(Event::End(BytesEnd::new(history_tag_element)))?;
        }

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        //debug!("End of writing the entry with Title {:?}", temp_title);
        Ok(())
    }

    fn write_entry(
        &mut self,
        entry_uuid: &uuid::Uuid,
        all_entries: &HashMap<uuid::Uuid, Entry>,
        in_history: bool,
    ) -> Result<()> {
        if let Some(entry) = all_entries.get(entry_uuid) {
            self.write_entry_data(entry, in_history)
        } else {
            Err(Error::DataError(
                "Writing entry failed as no value found in the lookup map",
            ))
        }
    }

    fn write_root(&mut self, kp: &KeepassFile) -> Result<()> {
        let tag_element = std::str::from_utf8(ROOT)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        self.write_group(
            &kp.root.root_uuid,
            &kp.root.all_groups,
            &kp.root.all_entries,
        )?;
        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }

    pub fn write(&mut self, kp: &KeepassFile) -> Result<()> {
        //<?xml version="1.0" encoding="utf-8" standalone="yes"?>
        self.writer.write_event(Event::Decl(BytesDecl::new(
            "1.0",
            Some("utf-8"),
            Some("yes"),
        )))?;

        let tag_element = std::str::from_utf8(KEEPASS_FILE)?;

        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;
        self.write_meta(kp)?;
        self.write_root(kp)?;
        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;
        Ok(())
    }
}

pub fn write_xml(
    kp: &KeepassFile,
    cipher: Option<ProtectedContentStreamCipher>,
) -> Result<Vec<u8>> {
    log::debug!("Going to write the xml string ...");
    let mut xml_writer = XmlWriter::new(Cursor::new(Vec::new()), cipher);
    xml_writer.write(kp)?;
    // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
    let v = xml_writer.writer.into_inner().into_inner();
    //debug!("In write_xml method: XML content is \n {}", std::str::from_utf8(&v).unwrap()); //Need to use {} and not the debug one {:?} to avoid \" in the print
    Ok(v)
}

pub fn write_xml_with_indent(
    kp: &KeepassFile,
    cipher: Option<ProtectedContentStreamCipher>,
) -> Result<Vec<u8>> {
    log::info!("Going to write the xml string ...");
    let mut xml_writer = XmlWriter::new_with_indent(Cursor::new(Vec::new()), cipher);
    xml_writer.write(kp)?;
    // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
    let v = xml_writer.writer.into_inner().into_inner();
    //println!("In write_xml method: XML content is \n {}", std::str::from_utf8(&v).unwrap()); //Need to use {} and not the debug one {:?} to avoid \" in the print
    Ok(v)
}

////////////////////////  Xml based Key file ////////////////

// For now FileKeyXmlReader and FileKeyXmlWriter are using similar struct XmlReader and XmlWriter
// but with FileKey xml specific methods supported
pub struct FileKeyXmlReader<'a> {
    reader: QuickXmlReader<&'a [u8]>,
    // We need this dummy member just to reuse the macros that are used for reading and writing databse xml content
    stream_cipher: Option<ProtectedContentStreamCipher>,
}

impl<'a> FileKeyXmlReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        let mut qxmlreader = QuickXmlReader::from_reader(data);
        qxmlreader.trim_text(true);
        FileKeyXmlReader {
            reader: qxmlreader,
            stream_cipher: None,
        }
    }

    pub fn parse(&mut self) -> Result<KeyFileData> {
        let mut buf: Vec<u8> = vec![];
        let mut xml_decl_available = false;
        let mut key_file_data = KeyFileData::default();
        loop {
            match self.reader.read_event_into(&mut buf) {
                Ok(Event::Decl(ref _e)) => {
                    xml_decl_available = true;
                    // return Err(Error::NotXmlKeyFile);
                }
                Ok(Event::DocType(_)) => {}
                Ok(Event::PI(_)) => {}
                Ok(Event::Text(_)) => {}

                Ok(Event::Start(ref e)) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                        // return Err(Error::XmlReadingFailed(format!(
                        //     "Xml content does not have XML decl"
                        // )));
                    }
                    match e.name().as_ref() {
                        KEY_FILE => {
                            let _r = self.read_top_level(&mut key_file_data)?;
                        }
                        x => {
                            //debug!("MAIN: in match {:?}", std::str::from_utf8(e.name()).unwrap());
                            //debug!("MAIN: in match {:?} KEEPASS_FILE", std::str::from_utf8(KEEPASS_FILE).unwrap());
                            return Err(Error::XmlReadingFailed(format!(
                                "Unexpected starting tag {:?}",
                                std::str::from_utf8(x)
                            )));
                        }
                    }
                }

                Ok(Event::Empty(ref _e)) => {}
                Ok(Event::End(ref _e)) => {
                    // KeyFile end tag should have been consumed in read_top_level
                    //info!("PARSE:End of tag {:?}", self.reader.decode(e));
                }

                Ok(Event::CData(ref _e)) => {}

                Ok(Event::Comment(ref _e)) => {}

                Ok(Event::Eof) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                    }
                    break;
                }

                Err(e) => {
                    if !xml_decl_available {
                        return Err(Error::NotXmlKeyFile);
                    } else {
                        return Err(Error::from(e));
                    }
                }
            }
        }
        Ok(key_file_data)
    }

    fn read_top_level(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {},
            start_tag_blks {
                KEY_FILE_META => {
                    self.read_meta(key_file_data)?;
                },
                KEY_FILE_KEY => {
                    self.read_key(key_file_data)?;
                }
            },
            empty_tags {},
            KEY_FILE);

        Ok(())
    }

    fn read_meta(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                KEY_FILE_VERSION =>
                (|content:String, _,  _|
                    key_file_data.version  = Some(content)
                )
            },
            start_tag_blks {},
            empty_tags {},
            KEY_FILE_META
        );

        if key_file_data.version.is_none() || key_file_data.version != Some("2.0".into()) {
            return Err(Error::UnsupportedXmlKeyFileVersion);
        }

        Ok(())
    }

    fn read_key(&mut self, key_file_data: &mut KeyFileData) -> Result<()> {
        read_tags!(self,
            start_tag_fns {
                KEY_FILE_DATA =>
                (|content:String, attributes:&mut Attributes,  _| {
                    let format_removed_content = Self::remove_formatting(&content);
                    key_file_data.data  = Some(format_removed_content);
                    key_file_data.hash = Self::read_data_hash(attributes);
                })
            },
            start_tag_blks {},
            empty_tags {},
            KEY_FILE_KEY
        );

        Ok(())
    }

    #[inline]
    fn remove_formatting(data: &str) -> String {
        data.split_whitespace()
            .map(|s| s)
            .collect::<Vec<_>>()
            .join("")
    }

    fn read_data_hash(attributes: &mut Attributes) -> Option<String> {
        let mut data_hash: Option<String> = None;
        let mut v = attributes
            .by_ref()
            .filter_map(|a| a.ok())
            .collect::<Vec<_>>();
        // Expected at leaset one attribute or no attributes for the the tag <Data>
        // e.g <Data Hash="F205E6EB">
        if !v.is_empty() {
            match v.pop() {
                Some(Attribute {
                    key: QName(KEY_FILE_DATA_HASH),
                    value: x,
                }) => {
                    //debug!("!!!!!! in fn attributes of Value are {:?}",v);
                    if let std::borrow::Cow::Borrowed(a) = x {
                        // println!("@@@@ a is {:?}", std::str::from_utf8(a).ok());
                        data_hash = std::str::from_utf8(a).map(|s| s.to_string()).ok();
                    }
                }
                // Log as error if these happen when reading other KeePass app generated
                // xml. This may happen if such apps introduce app specific changes. So far we never saw these
                Some(x) => error!(
                "Some unexpected attribute {:?} for the protected value for String -> Value tag",
                x
            ),
                None => error!("No protected attribute for this Value tag - String -> Value tag"),
            }
        }

        data_hash
    }
}

pub struct FileKeyXmlWriter<W: Write> {
    writer: QuickXmlWriter<W>,
}

impl<W: Write> FileKeyXmlWriter<W> {
    pub fn new_with_indent(writer: W) -> Self {
        Self {
            writer: QuickXmlWriter::new_with_indent(writer, b" "[0], 2),
        }
    }

    fn write_meta(&mut self, _key_file_data: &KeyFileData) -> Result<()> {
        let tag_element = std::str::from_utf8(KEY_FILE_META)?;
        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;

        write_tags! { self,
            KEY_FILE_VERSION, "2.0"
        };
        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        Ok(())
    }

    fn write_key_data(&mut self, key_file_data: &KeyFileData) -> Result<()> {
        let h = key_file_data
            .hash
            .as_ref()
            .map_or_else(|| "".into(), |s| s.clone());
        let d = key_file_data
            .data
            .as_ref()
            .map_or_else(|| "".into(), |s| s.clone());

        let fs = Self::format_hash_data(&d);
        write_parent_child_with_attributes! {
            self,
            KEY_FILE_KEY,
            KEY_FILE_DATA, vec![("Hash", h.as_str())], fs.as_str()

        };
        Ok(())
    }

    // These formatting are not required. As other implementations are formatting the
    // key xml file, a simple formatting attempt is done here
    fn format_hash_data(data: &str) -> String {
        // Splits the full hex string into 8 sub strings of each size 8
        let r = util::sub_strings(data, 8);
        // Split the vec r into two groups of 4 members each
        let ss = r.split_at(4);
        // Form str from each group
        let s1 = ss.0.to_vec().join(" ");
        let s2 = ss.1.to_vec().join(" ");
        // Final formatted text to use as Text of <Data> tag
        vec!["\n          ", &s1, "\n          ", &s2, "\n    "].join("")
    }

    pub fn write(&mut self, key_file_data: &KeyFileData) -> Result<()> {
        self.writer
            .write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;

        let tag_element = std::str::from_utf8(KEY_FILE)?;

        self.writer
            .write_event(Event::Start(BytesStart::new(tag_element)))?;

        self.write_meta(key_file_data)?;
        self.write_key_data(key_file_data)?;

        self.writer
            .write_event(Event::End(BytesEnd::new(tag_element)))?;

        Ok(())
    }
}

// cargo test test_mod_name::test_fn_name -- --exact
// Need to use " cargo test -- --nocapture " to see println! output in the console
// cargo test -- --show-output
// To use "env_logger" in tests use 'RUST_LOG=xml_parse=info cargo test read_sample_xml'
// However, Log events will be captured by `cargo` and only printed if the test fails. So see all log messages
// the test needs to fail !

#[cfg(test)]
mod tests {

    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    // To see logging output during testing in VS Code
    fn init() {
        let _ = env_logger::builder()
            // Include all events in tests
            .filter_level(log::LevelFilter::max())
            // Ensure events are captured by `cargo test`
            .is_test(true)
            // Ignore errors initializing the logger if tests race to configure it
            .try_init();
    }

    fn test_file(name: &str) -> PathBuf {
        let mut path = env::current_dir().unwrap();
        //println!("The current directory is {}", path.display());
        path.push("test_data");
        path.push(name);
        //println!("The current directory is {}", path.display());
        path
    }

    #[test]
    fn escape_test() {
        let s = "asddaads\nKim's idea";
        let es = quick_xml::escape::escape(s);
        //println!("escaped {:?}", es);
        assert_eq!(es,"asddaads\nKim&apos;s idea");

        let ues = quick_xml::escape::unescape(&es);
        //println!("unescaped {:?}", ues);
        assert!(ues.is_ok());
        assert_eq!(ues.unwrap(),"asddaads\nKim's idea");

        // Here unicode U+2019 ’ is used and that is not escaped
        let es2 = "My name&amp;apos;s none ddd\n\nThe name’s of nature….  Boy’s name\n\n";
        let ues2 = quick_xml::escape::unescape(es2);
        //println!("unescaped {:?}", ues2);
        assert!(ues2.is_ok());
        // &amp;apos;s on unescape &apos;s 
        // Only &amp;  -> &
        assert_eq!(ues2.unwrap(),"My name&apos;s none ddd\n\nThe name’s of nature….  Boy’s name\n\n");
    }

    #[test]
    fn read_sample_text_xml() {
        init();
        log::info!("This record will be captured by `cargo test`");
        let xml = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <KeePassFile>
            <Meta> 
                <Generator>OneKeePass</Generator> 
            </Meta>
            <UnhandledTag> </UnhandledTag> 
            <Root> 
                <Group>
                    <UUID>3aBY+AcLQmiPas0vjK2zng==</UUID>
                    <Name>Root</Name>
                    <Notes>Some text comes here</Notes>
                    <IconID>48</IconID>
                    <Times>
                        <CreationTime>J9pg1g4AAAA=</CreationTime>
                        <LastModificationTime>J9pg1g4AAAA=</LastModificationTime>
                        <LastAccessTime>/OZp2A4AAAA=</LastAccessTime>
                        <ExpiryTime>J9pg1g4AAAA=</ExpiryTime>
                        <Expires>False</Expires>
                        <UsageCount>4</UsageCount>
                        <LocationChanged>J9pg1g4AAAA=</LocationChanged>        
                    </Times>
                    <Group>
                        <Name>MyGroup1</Name>
                        <UUID>RRITlCo4TMKXYUPQ09yAvw==</UUID>
                        <IconID>59</IconID>
                        <Tags/>
                        <Notes>This is my first group.
                            Hello first</Notes>
                        <IsExpanded>True</IsExpanded>
                        <Entry>
                            <UUID>+Hf3wkQhQ46qUntgLmDGYw==</UUID>
                            <IconID>59</IconID>
                            <Tags/>
                            <Times>
                                <LastModificationTime>MNxg1g4AAAA=</LastModificationTime>
                                <CreationTime>b9tg1g4AAAA=</CreationTime>
                                <LastAccessTime>MNxg1g4AAAA=</LastAccessTime>
                                <ExpiryTime>b9tg1g4AAAA=</ExpiryTime>
                                <Expires>False</Expires>
                                <UsageCount>0</UsageCount>
                            </Times>
                                <String>
                                    <Key>UserName</Key>
                                    <Value>user1</Value>
                                </String>
                                <String>
                                    <Key>Column1</Key>
                                    <Value>This is first column</Value>
                                </String>
                                <String>
                                    <Key>Column2</Key>
                                    <Value Protected="True">dO2DjqfKUa3T7JNh3O0=</Value>
                                </String>
                                <String>
                                    <Key>Password</Key>
                                    <Value Protected="True">g2nZrW/E2dZyTpU=</Value>
                                </String>
                                <String>
                                    <Key>Notes</Key>
                                    <Value>For oracle</Value>
                                </String>
                                <String>
                                    <Key>Title</Key>
                                    <Value>My Title 1</Value>
                                </String>
                                <String>
                                    <Key>URL</Key>
                                    <Value>https://www.oracle.com</Value>
                                </String>
                                <CustomData>
                                </CustomData>
                                <AutoType>
                                    <Enabled>True</Enabled>
                                    <DefaultSequence/>
                                </AutoType>
                                <History>
                                </History>
                            </Entry>
                    </Group>
                </Group>
            </Root>
        </KeePassFile>
        "#;

        let mut reader = XmlReader::new(xml.as_bytes(), None);
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert_eq!(r.is_ok(), true);
        println!(" Kp is {:?}", r.unwrap());
    }

    #[test]
    fn read_sample_xml_fail1() {
        init();
        log::info!("End tag is missing");
        // <!-- No end tag -->
        let xml = r#"
        <?xml version="1.0" encoding="utf-8" standalone="yes"?>
        <KeePassFile>
            <Meta> 
        </KeePassFile>
        "#;

        let mut reader = XmlReader::new(xml.as_bytes(), None);
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert_eq!(r.is_err(), true);
    }

    #[test]
    fn read_sample_xml() {
        init();
        log::info!("This record will be captured by `cargo test`");
        let file_name = test_file("PasswordsXC1-Tags.xml"); //PasswordsXC1-Tags.xml
                                                            //let file_name = "/path/to/test_file.xml".to_string();
        let file_name =
            "/Users/jeyasankar/mytemp/Keepass-sample/RustDevSamples/xml/PasswordsXC1-Tags.xml";
        // This is the inner stream key used to decrypt the Protected data. This should have been the key
        // used to encrypt the protected data in this test xml file
        let key = vec![
            42u8, 60, 253, 132, 99, 97, 132, 162, 253, 31, 45, 229, 230, 138, 239, 197, 67, 148,
            33, 95, 61, 173, 215, 65, 108, 76, 108, 45, 127, 145, 70, 170, 3, 169, 234, 244, 250,
            160, 189, 73, 146, 131, 226, 102, 250, 198, 17, 140, 102, 145, 185, 162, 71, 181, 212,
            222, 210, 61, 150, 150, 242, 57, 151, 126,
        ];

        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();
        //Read the test xml file
        let d = fs::read(file_name).unwrap();
        let mut reader = XmlReader::new(&d[..], Some(cipher));
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert_eq!(r.is_ok(), true);
        println!(" Kp is {:?}", r.unwrap());
    }

    #[test]
    fn read_write_sample_xml() {
        let file_name = test_file("PasswordsXC1-Tags.xml"); //TODO Need to add this test xml to repo
                                                            // Using local sample KeePass xml content
        let file_name =
            "/Users/jeyasankar/mytemp/Keepass-sample/RustDevSamples/xml/PasswordsXC1-Tags.xml";

        //This is the inner stream key used to decrypt the Protected data of sunch as password in this particular xml content
        // This key will not work with other xml content!
        let key = vec![
            42u8, 60, 253, 132, 99, 97, 132, 162, 253, 31, 45, 229, 230, 138, 239, 197, 67, 148,
            33, 95, 61, 173, 215, 65, 108, 76, 108, 45, 127, 145, 70, 170, 3, 169, 234, 244, 250,
            160, 189, 73, 146, 131, 226, 102, 250, 198, 17, 140, 102, 145, 185, 162, 71, 181, 212,
            222, 210, 61, 150, 150, 242, 57, 151, 126,
        ];

        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();
        //Read the test xml file
        let d = fs::read(file_name).unwrap();
        let mut reader = super::XmlReader::new(&d[..], Some(cipher));
        let r = reader.parse();
        if let Err(e) = &r {
            println!("Error is {:?}", e);
        }
        assert_eq!(r.is_ok(), true);

        let cipher = ProtectedContentStreamCipher::try_from(3, &key).unwrap();
        let kp = r.unwrap();

        let write_result = write_xml_with_indent(&kp, Some(cipher));
        if let Err(e) = &write_result {
            println!("Error is {:?}", e);
        }
        assert_eq!(write_result.is_ok(), true);

        // Use the following to print the xml content output to the console for visual inspection

        // let xml_content = write_result.unwrap();
        // // Need to use {} and not the debug one {:?} to avoid \" in the printed output
        // println!(
        //     "XML content is \n {}",
        //     std::str::from_utf8(&xml_content).unwrap()
        // );
    }

    /// Key xml file related reading and writing tests
    #[test]
    fn verify_reading_file_key_xml() {
        // Data text is formatted
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        <KeyFile>
            <Meta>
                <Version>2.0</Version>
            </Meta>
            <Key>
                <Data Hash="F205E6EB">
                    ABA681B2 C6E19C74 E671EDEC 41D5AC09
                    9089F4B4 605937B5 B3E211AD 0056B325
                </Data>
            </Key>
        </KeyFile>
        "#;

        // Data text is one line
        // let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
        // <KeyFile>
        //     <Meta>
        //         <Version>2.0</Version>
        //     </Meta>
        //     <Key>
        //         <Data Hash="F205E6EB">ABA681B2C6E19C74E671EDEC41D5AC099089F4B4605937B5B3E211AD0056B325</Data>
        //     </Key>
        // </KeyFile>
        // "#;

        let mut reader = FileKeyXmlReader::new(xml.as_bytes());

        let r: Result<KeyFileData> = reader.parse();

        assert!(r.is_ok());
        let r1 = r.unwrap();
        println!(" r1 is {:?}", r1);
        assert!(r1.verify_checksum().is_ok());
    }

    #[test]
    fn verify_write_file_key_xml() {
        let data = "ABA681B2C6E19C74E671EDEC41D5AC099089F4B4605937B5B3E211AD0056B325";

        let key_file_data = KeyFileData {
            version: Some("2.0".into()),
            hash: Some("F205E6EB".into()),
            data: Some(data.into()),
        };

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(Cursor::new(Vec::new()));
        let w = xml_writer.write(&key_file_data);
        assert!(w.is_ok());

        // First into_inner() returns the inner writer Cursor and second into_inner() gives the underlying 'Vec'
        let v = xml_writer.writer.into_inner().into_inner();
        let xs = std::str::from_utf8(&v).unwrap();

        // println!("In write_xml method: XML content is \n{}", &xs);

        // Read back and verify
        let mut reader = FileKeyXmlReader::new(xs.as_bytes());
        let r: Result<KeyFileData> = reader.parse();
        assert!(r.is_ok());
        let r1 = r.unwrap();

        assert!(r1.verify_checksum().is_ok());
    }

    #[test]
    fn verify_generate_xml_key() {
        let r = KeyFileData::generate_key_data();
        let key_file_data = r.unwrap();

        //println!("kd is {:?}",key_file_data);

        let mut xml_writer = FileKeyXmlWriter::new_with_indent(Cursor::new(Vec::new()));
        let w = xml_writer.write(&key_file_data);
        assert!(w.is_ok());

        let v = xml_writer.writer.into_inner().into_inner();
        let xs = std::str::from_utf8(&v).unwrap();

        //println!("In write_xml method: XML content is \n{}", &xs);

        // Read back and verify
        let mut reader = FileKeyXmlReader::new(xs.as_bytes());
        let r: Result<KeyFileData> = reader.parse();
        assert!(r.is_ok());
        let r1 = r.unwrap();

        assert!(r1.verify_checksum().is_ok());
    }
}
