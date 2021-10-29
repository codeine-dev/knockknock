use std::{ffi::OsStr, path::PathBuf};

use rocket::http::ContentType;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/src/assets/"]
pub struct Assets;

#[derive(Responder, Debug)]
pub enum AssetData {
    Bytes(Vec<u8>),
    #[response(status = 400)]
    BadRequest(&'static str),
    #[response(status = 404)]
    NotFound(&'static str),
}

#[get("/assets/<file..>")]
pub fn assets(file: PathBuf) -> (ContentType, AssetData) {
    let filename = file.display().to_string();
    Assets::get(&filename).map_or_else(
        || (ContentType::Plain, AssetData::NotFound("")),
        |d| {
            let ext = file
                .as_path()
                .extension()
                .and_then(OsStr::to_str)
                .ok_or_else(|| AssetData::BadRequest("Missing extension"));

            if let Err(ext) = ext {
                return (ContentType::Plain, ext);
            }

            let ext = ext.unwrap();
            let content_type = ContentType::from_extension(ext);

            if content_type.is_none() {
                return (
                    ContentType::Plain,
                    AssetData::BadRequest("Unknown content type"),
                );
            }

            let content_type = content_type.unwrap();
            (content_type, AssetData::Bytes(d.data.to_vec()))
        },
    )
}
