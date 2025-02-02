use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while},
    character::{
        complete::{multispace0, one_of},
        is_hex_digit,
    },
    combinator::{map, rest},
    sequence::{delimited, preceded, terminated, tuple},
    IResult, Parser,
};

use crate::{
    constants::entry_keyvalue_key::*,
    db_content::{Entry, Root},
    error::{self, Result},
};

// static STANDARD_FIELDS: OnceLock<HashSet<&'static str>> = OnceLock::new();

// fn standard_fields() -> &'static HashSet<&'static str> {
//     //STANDARD_FIELDS.get_or_init(|| HashSet::from(["TITLE", "USERNAME", "PASSWORD", "URL", "NOTES"]))
//     STANDARD_FIELDS.get_or_init(|| HashSet::from(["URL", "USERNAME", "PASSWORD", "TITLE", "NOTES"]))
// }

#[derive(Debug, PartialEq, Eq)]
enum FieldNameResolver<'a> {
    NameExtracted {
        left: &'a str,
        name: &'a str,
        right: &'a str,
    },
    Completed(&'a str),
}

/*
{REF:<WantedField>@<SearchIn>:<Text>}
The Text part is the search string that describes the text(s)
that must occur in the specified field of an entry to match.
If multiple entries match the specified search criterion, the value from first entry will be used.

Example:
When we use {REF:P@I:46C9B1FFBD4ABC4BBB260C6190BAD20C} in a field (may be in username or in password or in title or in notes)
of an entry, that would be replaced with the password of the entry having 46C9B1FFBD4ABC4BBB260C6190BAD20C as UUID.

Meaning 'Use the password of the entry 46C9B1FFBD4ABC4BBB260C6190BAD20C here
*/
#[derive(Debug, PartialEq)]
enum ReferenceField {
    Title,
    Password,
    UserName,
    Url,
    Notes,
    Uuid,
    CustomField,
    //Unknown,
}

impl ReferenceField {
    fn from(field_letter: char) -> Self {
        match field_letter {
            'T' => ReferenceField::Title,
            'U' => ReferenceField::UserName,
            'P' => ReferenceField::Password,
            'A' => ReferenceField::Url,
            'N' => ReferenceField::Notes,
            'I' => ReferenceField::Uuid,
            'O' => ReferenceField::CustomField,
            // This will panic
            // Using this fine as long as we use 'one_of("TUPANIO")' parsing
            _ => unreachable!("ReferenceField letter matching exhausted"),
            //_ => ReferenceField::Unknown,
        }
    }

    fn as_char(&self) -> char {
        use ReferenceField::*;
        match self {
            Title => 'T',
            UserName => 'U',
            Password => 'P',
            Url => 'A',
            Notes => 'N',
            Uuid => 'I',
            CustomField => 'O',
        }
    }

    fn field_name(&self) -> &str {
        use ReferenceField::*;
        match self {
            Title => TITLE,
            UserName => USER_NAME,
            Password => PASSWORD,
            Url => URL,
            Notes => NOTES,
            _ => "NOT_A_STANDARD_FIELD", // Uuid => "UUID",
                                         // CustomField => ,
        }
    }
}

#[derive(Debug)]
struct ReferenceFieldParsed {
    wanted_field: ReferenceField,
    search_in_field: ReferenceField,
    text_or_uuid: String,
}

impl ReferenceFieldParsed {
    fn from(wanted_field: char, search_in_field: char, text_or_uuid: &str) -> ReferenceFieldParsed {
        ReferenceFieldParsed {
            wanted_field: ReferenceField::from(wanted_field),
            search_in_field: ReferenceField::from(search_in_field),
            text_or_uuid: text_or_uuid.to_string(),
        }
    }

    fn parse_matched_entry(
        &self,
        entry_place_holder_parser: &mut EntryPlaceHolderParser,
        entry: &Entry,
        depth_counter: usize,
    ) -> Option<String> {
        // Need to set the incremented depth_counter in the calling 'entry_place_holder_parser'
        entry_place_holder_parser.depth_counter = depth_counter;

        // Find the wanted field in the passed entry
        let Some(kv) = entry.find_kv_field_value(&self.wanted_field.field_name()) else {
            return None;
        };

        // First we check to whether we need to do the place holder resolving for the retrived value
        if place_holder_marker_found(&kv) {
            // We go till tenth level looking for uuid matching
            if depth_counter > 10 {
                return None;
            }

            // Ensure that place holder resolving is done for all KVs of this entry
            let mut entry_fields = entry.extract_place_holders();

            // println!("New EntryPlaceHolderParser is created for the next entry");

            let mut ef = EntryPlaceHolderParser::from(
                entry_place_holder_parser.root,
                entry,
                &mut entry_fields,
            );
            // Note the use of depth_counter
            if let Err(e) = ef.parse_main(depth_counter) {
                log::error!("parse_matched_entry failed {}", e);
                return None;
            }
            // Any value found for the 'wanted_field' is returned or None
            entry_fields
                .get(&self.wanted_field.field_name().to_uppercase())
                .cloned()
        } else {
            // No place holder resolving is required and the value of field is returned
            Some(kv)
        }
    }

    fn default_unparsed(&self) -> String {
        // Note if we "{{REF:{}@{}:{}}}", the recurive call in EntryPlaceHolderParser.parse()
        // may call this REF parsing again and again (need to check possible use cases)
        // Because of that "REF:{}@{}:{}" is used

        format!(
            "REF:{}@{}:{}",
            &self.wanted_field.as_char(),
            &self.search_in_field.as_char(),
            &self.text_or_uuid
        )
    }

    // Called from entry_place_holder_parser's parse fn
    fn parse(
        &self,
        entry_place_holder_parser: &mut EntryPlaceHolderParser,
        depth_counter: usize,
    ) -> String {
        // For now we support only Uuid search
        // All other search_field ('P', 'T', ..) may be done latter as it involves searching using
        // text matching and using the first entry that metaches that text search

        // Should depth_counter check needs to be done here or in 'parse_matched_entry'
        // self.search_in_field != ReferenceField::Uuid || depth_counter > 3
        if self.search_in_field != ReferenceField::Uuid {
            println!("Only uuid search_in_field is supported and returing REF string itself");
            return self.default_unparsed();
        }

        if let Ok(ref entry_uuid) = uuid::Uuid::parse_str(&self.text_or_uuid) {
            if entry_uuid == entry_place_holder_parser.current_entry.get_uuid() {
                // We are using a field (wanted_field) from the currrent entry for this uuid search_in_field
                return entry_place_holder_parser
                    .entry_fields
                    .get(self.wanted_field.field_name())
                    .map_or_else(|| self.default_unparsed(), |s| s.clone());
            }
            // println!( "Matching entry is not found and depth_counter {}",depth_counter);

            // Need to find the entry and then find the value of the 'wanted_field' in that entry
            // If we do not find an entry with this uuid or no value is found, then we just return the ref string itself
            let out = entry_place_holder_parser
                .root
                .entry_by_id(entry_uuid)
                .map(|entry_found| {
                    // depth_counter is incremented as we are looking for 'wanted_field' in the next entry
                    self.parse_matched_entry(
                        entry_place_holder_parser,
                        entry_found,
                        depth_counter + 1,
                    )
                })
                .flatten()
                .unwrap_or(self.default_unparsed());
            out
        } else {
            // This happens if the uuid string extracted is an invalid one
            log::error!("Invalid UUID found in the reference");
            println!("Invalid UUID found in the reference");
            format!("Invalid-{}", &self.text_or_uuid)
        }
    }
}

#[derive(Debug)]
pub(crate) struct EntryPlaceHolderParser<'a> {
    modified_fields: Vec<String>,
    root: &'a Root,
    current_entry: &'a Entry,
    current_field_name: Option<String>,
    depth_counter: usize,
    entry_fields: &'a mut HashMap<String, String>,
}

impl<'a> EntryPlaceHolderParser<'a> {
    fn from(
        root: &'a Root,
        current_entry: &'a Entry,
        entry_fields: &'a mut HashMap<String, String>,
    ) -> Self {
        EntryPlaceHolderParser {
            modified_fields: vec![],
            root,
            current_entry,
            entry_fields,
            current_field_name: None,
            depth_counter: 1,
        }
    }

    pub(crate) fn resolve_place_holders(
        root: &'a Root,
        entry: &'a Entry,
    ) -> HashMap<String, String> {
        let mut entry_fields_with_place_holders = entry.extract_place_holders();

        if !entry_fields_with_place_holders.is_empty() {
            let mut ef =
                EntryPlaceHolderParser::from(root, entry, &mut entry_fields_with_place_holders);
            if let Err(e) = ef.parse_main(1) {
                log::error!("EntryPlaceHolderParser parsing failed {}", e);
                return HashMap::default();
            }

            let modified = ef.modified_fields();

            entry_fields_with_place_holders.retain(
                |k, _v| {
                    if modified.contains(k) {
                        true
                    } else {
                        false
                    }
                },
            );
        }

        entry_fields_with_place_holders
    }

    pub(crate) fn modified_fields(&self) -> Vec<String> {
        self.modified_fields.clone()
    }

    pub(crate) fn _print(&self) {
        println!(
            "modified_fields:{:?}, \n entry_fields:{:?}",
            self.modified_fields, self.entry_fields
        );
    }
}

impl<'a> EntryPlaceHolderParser<'a> {
    pub(crate) fn parse_main(&mut self, depth_counter: usize) -> Result<()> {
        let keys = self
            .entry_fields
            .keys()
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        // for k in standard_fields()
        for k in keys {
            // entry_fields keys are in uppercase

            if let Some(v) = self.entry_fields.get(&k) {
                let to_be_parsed = v.to_string();

                // println!("Going to parse for k {} , v {}", &k, &to_be_parsed);

                self.current_field_name = Some(k.to_string());
                self.depth_counter = depth_counter;

                if let Ok(r) = self.parse(to_be_parsed.clone(), depth_counter) {
                    // println!("Parsing is done for k {} , r {}", &k, &r);
                    if to_be_parsed != r && self.depth_counter < 10 {
                        // println!("Inserting parsed value for k {} , r {}", &k, &r);
                        self.modified_fields.push(k.to_string());
                        self.entry_fields.insert(k.to_string(), r);
                    }
                }
            }
        }
        Ok(())
    }

    fn next_parsing(
        &mut self,
        left: &str,
        name: &str,
        right: &str,
        depth_counter: usize,
    ) -> Result<String> {
        let name_str = name.trim().to_uppercase().to_string();

        // println!("---- next parsing is called for left: {} , name: {} , right: {} ",left, name, right );

        // No point of continuing for the same field again and according the call returns early
        // let early_return = self.current_field_name.as_ref().map_or_else(
        //     || false,
        //     |f| {
        //         // println!("Checking early_return current field {}, name_str {}, counter {} ",f,&name_str,depth_counter);
        //         (f == &name_str) && (depth_counter > 1)
        //     },
        // );

        // if early_return {
        //     println!("Returning early for name {}", &name);
        //     return Ok(format!("{}{{{}}}{}", left, name, right));
        // }

        if tag::<&str, &str, nom::error::Error<_>>("REF:")
            .parse(name)
            .is_ok()
        {
            if let Ok((_, ref_parsed)) = parse_reference_holder(name) {
                let ref_value = ref_parsed.parse(self, depth_counter);

                let next_val = format!("{}{}{}", left, &ref_value, right);
                // println!("Ref parse returning value {} ", &next_val);

                // We need to do this to ensure that 'next_val' is parsed again for any place holder on the 'right'
                // e.g right = "/{USERNAME}""

                // Will 'ref_value' returned have any other place holder?. Need to check

                self.parse(next_val, depth_counter + 1)

                /*
                // If we use the format "{{REF:{}@{}:{}}}" to return default value for ref_value,
                // then we may the following assuming ref_value does not have any other place holder
                
                // Or we can make self.parse on 'ref_value' and on 'right_val' separately and then combine to return as final value.
                
                // ref_value = self.parse(ref_value.to_string(), depth_counter + 1).unwrap_or(String::default());
                // if we call self.parse on 'ref_value' and it returns the same "{{REF:{}@{}:{}}}", to avoid looping again
                // we can store 'ref_value' and call self.parse only when returned value is not the same 
                // let local_ref_value = ref_value
                // ref_value = self.parse(ref_value.to_string(), depth_counter + 1).unwrap_or(String::default())
                

                let right_val = self.parse(right.to_string(), depth_counter + 1).unwrap_or(String::default());
                let next_val = format!("{}{}{}", left, &ref_value, right_val);
                Ok(next_val)
                */
            } else {
                Ok(format!("{}{}{}", left, name, right))
            }
        } else {
            if let Some(matching_field_value) = self.entry_fields.get(&name_str) {
                let next_val = format!("{}{}{}", left, matching_field_value, right);
                self.parse(next_val, depth_counter + 1)
            } else {
                Ok(format!("{}{{{}}}{}", left, name, right))
            }
        }
    }

    fn parse(&mut self, input: String, depth_counter: usize) -> Result<String> {
        self.depth_counter = depth_counter;

        if depth_counter > 10 {
            println!(
                "Parse depth counter exceed and returning {} for current field {:?}",
                &input, self.current_field_name
            );
            return Ok(input);
        }

        // alt gives us the result of first parser that succeeds, of the series of parsers we give it
        let mut parser = alt((field_parser(), no_field_parser()));

        match parser(input.as_str()) {
            // r.0 should be empty
            Ok(r) => match r.1 {
                FieldNameResolver::NameExtracted { left, name, right } => {
                    self.next_parsing(left, name, right, depth_counter)
                }
                FieldNameResolver::Completed(s) => Ok(s.to_string()),
            },
            Err(e) => {
                println!("Parsing error {}", e);
                Err(error::Error::UnexpectedError(format!(
                    "Parsing of string {} failed: error {} ",
                    &input, e
                )))
            }
        }
    }
}

fn field_parser<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, FieldNameResolver<'a>> {
    map(
        // tuple returns output for each parser listed in an output tuple
        tuple((take_until("{"), tag("{"), take_until("}"), tag("}"), rest)),
        // Here x is a tuple
        |x| FieldNameResolver::NameExtracted {
            left: x.0,
            name: x.2,
            right: x.4,
        },
    )
}

fn no_field_parser<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, FieldNameResolver<'a>> {
    map(rest, |x| FieldNameResolver::Completed(x))
}

fn parse_reference_holder<'a>(input: &'a str) -> IResult<&'a str, ReferenceFieldParsed> {
    let r = map(
        tuple((
            delimited(
                // multispace0 matches any leading space
                tuple((multispace0, tag("REF:"))),
                one_of("TUPANIO"),
                tag("@"),
            ),
            terminated(one_of("TUPANIO"), tag(":")),
            rest, // one_of("TUPANIO"),
                  // tag("@"),
                  // one_of("TUPANIO"),
                  // tag(":"),rest
        )),
        |x| ReferenceFieldParsed::from(x.0, x.1, x.2),
    )
    .parse(input)?; // need nom:Parser trait when we use 'parse' fn

    Ok(r)
}

fn check_place_holder_marker<'a>(input: &'a str) -> IResult<&'a str, bool> {
    map(
        tuple((take_until("{"), tag("{"), take_until("}"), tag("}"), rest)),
        |_| true,
    )(input)
}

pub(crate) fn place_holder_marker_found(input: &str) -> bool {
    check_place_holder_marker(input).map_or(false, |x| x.1)
}

//////////////////////////

#[cfg(test)]
mod tests {
    use super::parse_ref_val;
    use super::ReferenceParser;
    use super::*;

    fn parse1() {
        let mut entry_fields = HashMap::<String, String>::default();
        entry_fields.insert("TITLE".into(), "MyAccount-{USERNAME}".into());
        // entry_fields.insert("PASSWORD".into(), "John Doe {REF:U@I:5017C6460FED43FFB16FD85C0F875D0E}".into());

        entry_fields.insert("PASSWORD".into(), "John Doe {DB_NAME}".into());
        //m.insert("TITLE".into(), "{USERNAME}".into());
        entry_fields.insert(
            "USERNAME".into(),
            // "John Doe {URL}".into(),
            // "John Doe ".into(),
            // "John Doe {REF:U@I:5017C6460FED43FFB16FD85C0F875D0A}".into(),
            "John Doe {REF:U@A:some text}".into(),
        );
        //m.insert("PASSWORD".into(), "{REF:U@I:5017C6460FED43FFB16FD85C0F875D0A}".into());
        entry_fields.insert("URL".into(), "https:://{TITLE}/{USERNAME}".into());

        // let mut ef = EntryPlaceHolderParser {
        //     modified_fields: vec![],
        //     entry_fields: &mut m,
        // };

        let root = Root::new();
        let entry = Entry::new();
        let mut ef = EntryPlaceHolderParser::from(&root, &entry, &mut entry_fields);

        let r = ef.parse_main(1);

        println!(
            "\nparsed ef {:?} \n\n modified fields {:?}",
            &ef.entry_fields, &ef.modified_fields
        );
        //println!(" parse result is {:?}", &r)
    }

    #[test]
    fn verify1() {
        parse1();
        // let r = parse_reference_holder("REF:U@I:5017C6460FED43FFB16FD85C0F875D0A");
        // println!(" r is {:?}", r);

        // let r = field_parser()("No {URL} variables");
    }

    #[test]
    fn verify_main_parser() {
        let mut parser = alt((field_parser(), no_field_parser()));
        //let r = parser("https:://MyAccount-John Doe REF:U@I:5017C6460FED43FFB16FD85C0F875D0A/{USERNAME}");
        let r = parser("https:://{TITLE}/{USERNAME}");
        println!(" r is {:?}", r);
    }

    #[test]
    fn verify2() {
        let r = parse_reference_holder(" REF:U@I:5017C6460FED43FFB16FD85C0F875D0A");
        println!(" r is {:?}", r);
    }

    #[test]
    fn verify3() {
        let val1 = "{REF:U@I:5017C6460FED43FFB16FD85C0F875D0A}";
        let r = parse_ref_val("{REF:U@I:", val1);
        println!("Parsed {:?}", &r);

        let r = ReferenceParser::parse("{REF:U@I:", val1);
        println!("Parsed2  {:?}", &r);
    }
}

#[derive(Debug)]
struct ReferenceParser<'a> {
    uuid_str: &'a str,
}

impl<'a> ReferenceParser<'a> {
    fn parse(ref_prefix: &'a str, value: &'a str) -> IResult<&'a str, ReferenceParser<'a>> {
        let r = preceded(
            tag(ref_prefix),
            terminated(take_while(|c| is_hex_digit(c as u8)), tag("}")),
        )(value)?;

        Ok((r.0, ReferenceParser { uuid_str: r.1 }))
    }
}

fn parse_ref_val<'a>(ref_prefix: &'a str, value: &'a str) -> IResult<&'a str, &'a str> {
    let r = preceded(
        tag(ref_prefix),
        terminated(take_while(|c| is_hex_digit(c as u8)), tag("}")),
    )(value)?;

    Ok((r.0, r.1))
}

// {REF:U@I:5017C6460FED43FFB16FD85C0F875D0A}
// {REF:P@I:5017C6460FED43FFB16FD85C0F875D0A}

// fn fenced<'a>(start: &'a str, end: &'a str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
//     map(tuple((tag(start), take_until(end), tag(end))), |x| x.1)
// }

/*

fn verify_name_part(&mut self, name: &str) -> String {
        self.entry_fields
            .get(&name.trim().to_uppercase().to_string())
            .map_or(String::default(), |s| s.to_string())
    }

fn root_call(value: &str,) -> String {
    value.to_string()
}

fn ref_field_parser<'a>(holder:&mut EntryPlaceHolderParser) -> impl FnMut(&'a str) -> IResult<&'a str, FieldNameResolver<'a>> {
    map(
        // tuple returns output for each parser listed in an output tuple
        tuple((tag("REF:P@I:"), rest)),
        // Here x is a tuple
        |x| FieldNameResolver::ReferenceResolved(root_call(x.1))
    )
}

fn parse_ref_val1<'a>(ref_prefix: &'a str, value: &'a str) -> IResult<&'a str, &'a str> {
    let r = preceded(
        tag(ref_prefix),
        terminated(take_while(|c| is_hex_digit(c as u8)), tag("}")),
    )(value)?;

    Ok((r.0, r.1))
}


fn fenced_name<'a>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    map(
        // tuple returns output for each parser listed in an output tuple
        tuple((multispace0, tag("{"), take_until("}"), tag("}"))),
        // Here x is a tuple
        |x| x.2,
    )
}

fn parse1() {
    let mut m = HashMap::<String, String>::default();
    m.insert("TITLE".into(), "Title 1".into());
    m.insert("USERNAME".into(), "John Doe".into());

    if let Some(v) = m.get("TITLE") {}

    let r = field_parser()("&* 12312 Hello {TITLE} ");
    //let r = field_parser("TITLE")("&* 12312 Hello {TITLE} world");

    println!(" parse result is {:?}", &r)
}

fn field_parser<'a>(field_name: &'a str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    //preceded(tag("{"), terminated(tag(field_name), tag("}")))
    map(
        // tuple returns output for each parser listed in an output tuple

        // alt (
        //     (tuple((take_until("{"), tag("{"), tag(field_name), tag("}"))), rest)
        // ),
        tuple((take_until("{"), tag("{"), tag(field_name), tag("}"), rest)),
        // Here x is a tuple
        |x| {
            println!("x is {:?}", &x);
            x.2
        },
    )
}
fn field_parser<'a>(field_name:&'a str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str> {
    //preceded(tag("{"), terminated(tag(field_name), tag("}")))
    map(
        // tuple returns output for each parser listed in an output tuple
        // tuple((alpha1, multispace0,tag("{"), tag(field_name), tag("}"))),

        tuple((take_until("{"), tag("{"), tag(field_name), tag("}"))),
        // Here x is a tuple
        |x|  {
            println!("x is {:?}",&x);
            x.2
        },
      )
}

*/
