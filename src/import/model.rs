// Canonical representation an importer produces, sitting between a source format and
// the kdbx writer. Every importer (csv today, vendor json later) normalises into this,
// so group creation, entry type resolution and field writing exist in one place only.

// The entry kind an importer detected for an item. The writer resolves this to one of
// OKP's standard entry types.
//
// There is deliberately no SecureNote variant. KeePass and KeePassXC have no entry type
// system at all - a secure note there is just an entry with Title and Notes filled - and
// OKP follows that rather than introducing a divergence. Vendor "note" items therefore
// arrive as Login with only Notes populated.
// Deciding an item's kind needs a source "type" column, which only a per-exporter
// profile can identify, so a generic csv always produces Login. BankAccount is defined
// for symmetry but no profile maps a value onto it yet
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) enum ImportedKind {
    #[default]
    Login,
    CreditCard,
    Identity,
    BankAccount,
}

#[derive(Debug, Clone)]
pub(crate) struct ImportedField {
    // Entry field name. Either a standard kdbx field (Title, UserName ...) or the
    // source column name when the field is a custom one
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) protected: bool,

    // A field the source named itself rather than one of OKP's standard fields. The
    // writer has to declare these in the entry type's custom field section, otherwise
    // the entry form has nowhere to show them. Which names appear differs per item -
    // Bitwarden packs an item's own custom fields into a single column - so the section
    // is built per entry rather than once for the whole import
    pub(crate) custom: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportedItem {
    pub(crate) kind: ImportedKind,

    // Group names from the root downwards. Empty means the item has no folder and
    // belongs in the importer's default group. A single element is a flat group;
    // splitting a "Work/Clients" style path into several elements is a source-format
    // concern, not the writer's
    pub(crate) folder_path: Vec<String>,

    pub(crate) fields: Vec<ImportedField>,

    // Stored on the entry as-is. Normalising a comma separated vendor list into the
    // kdbx semicolon convention is done by the importer before it gets here
    pub(crate) tags: Option<String>,

    // Standard kdbx icon index the source gave the item. None leaves the entry with the
    // icon its entry type provides
    pub(crate) icon_id: Option<i32>,
}
