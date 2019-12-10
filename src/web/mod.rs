use rocket;
use rocket::http::{Header, Status};
use rocket::request;
use rocket::outcome::Outcome;
use rocket::response::{NamedFile, Responder, Response};
use rocket::config::Config;
use rocket_contrib::templates::{Template, Engines};
use rocket::http::uri::Uri;
use rocket_contrib::json::JsonValue;
use rocket::response::status::Custom;
use rocket_i18n::I18n;

use rocket_prometheus::PrometheusMetrics;

use gettext_macros::{compile_i18n, include_i18n};

use serde::Serialize;

use std::path::PathBuf;

use crate::mail;
use crate::tokens;
use crate::counters;
use crate::template_helpers::TemplateOverrides;
use crate::i18n::I18NHelper;
use crate::rate_limiter::RateLimiter;

use crate::database::{Database, KeyDatabase, Query};
use crate::database::types::Fingerprint;
use crate::Result;

use std::convert::TryInto;

mod hkp;
mod manage;
mod maintenance;
mod vks;
mod vks_web;
mod vks_api;
mod debug_web;

use crate::web::maintenance::MaintenanceMode;

use rocket::http::hyper::header::ContentDisposition;

pub struct HagridTemplate(&'static str, serde_json::Value);

impl Responder<'static> for HagridTemplate {
    fn respond_to(self, req: &rocket::Request) -> std::result::Result<Response<'static>, Status> {
        let HagridTemplate(tmpl, ctx) = self;
        let i18n: I18n = req.guard().expect("Error parsing language");
        let template_overrides: rocket::State<TemplateOverrides> = req.guard().expect("TemplateOverrides must be in managed state");
        let template_override = template_overrides.get_template_override(i18n.lang, tmpl);
        let origin: RequestOrigin = req.guard().expect("Error determining request origin");
        let layout_context = templates::HagridLayout::new(ctx, i18n, origin);

        if let Some(template_override) = template_override {
            Template::render(template_override, layout_context)
        } else {
            Template::render(tmpl, layout_context)
        }.respond_to(req)
    }
}

#[derive(Responder)]
pub enum MyResponse {
    #[response(status = 200, content_type = "html")]
    Success(HagridTemplate),
    #[response(status = 200, content_type = "plain")]
    Plain(String),
    #[response(status = 200, content_type = "xml")]
    Xml(HagridTemplate),
    #[response(status = 200, content_type = "application/pgp-keys")]
    Key(String, ContentDisposition),
    #[response(status = 200, content_type = "application/pgp-keys")]
    XAccelRedirect(&'static str, Header<'static>, ContentDisposition),
    #[response(status = 500, content_type = "html")]
    ServerError(Template),
    #[response(status = 404, content_type = "html")]
    NotFound(HagridTemplate),
    #[response(status = 404, content_type = "html")]
    NotFoundPlain(String),
    #[response(status = 400, content_type = "html")]
    BadRequest(HagridTemplate),
    #[response(status = 400, content_type = "html")]
    BadRequestPlain(String),
    #[response(status = 503, content_type = "html")]
    Maintenance(Template),
    #[response(status = 503, content_type = "json")]
    MaintenanceJson(JsonValue),
    #[response(status = 503, content_type = "plain")]
    MaintenancePlain(String),
}

impl MyResponse {
    pub fn ok(tmpl: &'static str, ctx: impl Serialize) -> Self {
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::Success(HagridTemplate(tmpl, context_json))
    }

    pub fn ok_bare(tmpl: &'static str) -> Self {
        let context_json = serde_json::to_value(templates::Bare { dummy: () }).unwrap();
        MyResponse::Success(HagridTemplate(tmpl, context_json))
    }

    pub fn xml(tmpl: &'static str) -> Self {
        let context_json = serde_json::to_value(templates::Bare { dummy: () }).unwrap();
        MyResponse::Xml(HagridTemplate(tmpl, context_json))
    }

    pub fn plain(s: String) -> Self {
        MyResponse::Plain(s)
    }

    pub fn key(armored_key: String, fp: &Fingerprint) -> Self {
        use rocket::http::hyper::header::{DispositionType, DispositionParam, Charset};
        MyResponse::Key(
            armored_key,
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![
                    DispositionParam::Filename(
                        Charset::Us_Ascii, None,
                        (fp.to_string() + ".asc").into_bytes()),
                ],
            })
    }

    pub fn x_accel_redirect(x_accel_path: String, fp: &Fingerprint) -> Self {
        use rocket::http::hyper::header::{DispositionType, DispositionParam, Charset};
        // nginx expects percent-encoded URIs
        let x_accel_path = Uri::percent_encode(&x_accel_path).into_owned();
        MyResponse::XAccelRedirect(
            "",
            Header::new("X-Accel-Redirect", x_accel_path),
            ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![
                    DispositionParam::Filename(
                        Charset::Us_Ascii, None,
                        (fp.to_string() + ".asc").into_bytes()),
                ],
            })
    }

    pub fn ise(e: failure::Error) -> Self {
        eprintln!("Internal error: {:?}", e);
        let ctx = templates::FiveHundred {
            internal_error: e.to_string(),
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
            lang: "en".to_string(),
        };
        MyResponse::ServerError(Template::render("500", ctx))
    }

    pub fn bad_request(template: &'static str, e: failure::Error) -> Self {
        let ctx = templates::Error { error: format!("{}", e) };
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::BadRequest(HagridTemplate(template, context_json))
    }

    pub fn bad_request_plain(message: impl Into<String>) -> Self {
        MyResponse::BadRequestPlain(message.into())
    }

    pub fn not_found_plain(message: impl Into<String>) -> Self {
        MyResponse::NotFoundPlain(message.into())
    }

    pub fn not_found(
        tmpl: Option<&'static str>,
        message: impl Into<Option<String>>,
    ) -> Self {
        let ctx = templates::Error { error: message.into()
                         .unwrap_or_else(|| "Key not found".to_owned()) };
        let context_json = serde_json::to_value(ctx).unwrap();
        MyResponse::NotFound(HagridTemplate(tmpl.unwrap_or("index"), context_json))
    }
}

mod templates {
    use super::{I18n, RequestOrigin};

    #[derive(Serialize)]
    pub struct FiveHundred {
        pub internal_error: String,
        pub commit: String,
        pub version: String,
        pub lang: String,
    }

    #[derive(Serialize)]
    pub struct HagridLayout<T: serde::Serialize> {
        pub error: Option<String>,
        pub commit: String,
        pub version: String,
        pub base_uri: String,
        pub lang: String,
        pub page: T,
    }

    #[derive(Serialize)]
    pub struct Error {
        pub error: String,
    }

    #[derive(Serialize)]
    pub struct Bare {
        // Dummy value to make sure {{#with page}} always passes
        pub dummy: (),
    }

    impl<T: serde::Serialize> HagridLayout<T> {
        pub fn new(page: T, i18n: I18n, origin: RequestOrigin) -> Self {
            Self {
                error: None,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
                base_uri: origin.get_base_uri().to_string(),
                page: page,
                lang: i18n.lang.to_string(),
            }
        }
    }
}

pub struct HagridState {
    /// Assets directory, mounted to /assets, served by hagrid or nginx
    assets_dir: PathBuf,

    /// The keys directory, where keys are located, served by hagrid or nginx
    keys_external_dir: PathBuf,

    /// XXX
    base_uri: String,
    base_uri_onion: String,

    /// 
    x_accel_redirect: bool,
    x_accel_prefix: Option<PathBuf>,
}

#[derive(Debug)]
pub enum RequestOrigin {
    Direct(String),
    OnionService(String),
}

impl<'a, 'r> request::FromRequest<'a, 'r> for RequestOrigin {
    type Error = ();

    fn from_request(request: &'a request::Request<'r>) -> request::Outcome<Self, Self::Error> {
        let hagrid_state = request.guard::<rocket::State<HagridState>>().unwrap();
        let result = match request.headers().get("x-is-onion").next() {
            Some(_) => RequestOrigin::OnionService(hagrid_state.base_uri_onion.clone()),
            None => RequestOrigin::Direct(hagrid_state.base_uri.clone()),
        };
        Outcome::Success(result)
    }
}

impl RequestOrigin {
    fn get_base_uri(&self) -> &str {
        match self {
            RequestOrigin::Direct(uri) => uri.as_str(),
            RequestOrigin::OnionService(uri) => uri.as_str(),
        }
    }
}

pub fn key_to_response_plain(
    state: rocket::State<HagridState>,
    db: rocket::State<KeyDatabase>,
    query: Query,
) -> MyResponse {
    let fp = if let Some(fp) = db.lookup_primary_fingerprint(&query) {
        fp
    } else {
        return MyResponse::not_found_plain(query.describe_error());
    };

    if state.x_accel_redirect {
        if let Some(key_path) = db.lookup_path(&query) {
            let mut x_accel_path = state.keys_external_dir.join(&key_path);
            if let Some(prefix) = state.x_accel_prefix.as_ref() {
                x_accel_path = x_accel_path.strip_prefix(&prefix).unwrap().to_path_buf();
            }
            // prepend a / to make path relative to nginx root
            let x_accel_path = format!("/{}", x_accel_path.to_string_lossy());
            return MyResponse::x_accel_redirect(x_accel_path, &fp);
        }
    }

    return match db.by_fpr(&fp) {
        Some(armored) => MyResponse::key(armored, &fp.into()),
        None => MyResponse::not_found_plain(query.describe_error()),
    }
}

#[get("/assets/<file..>")]
fn files(file: PathBuf, state: rocket::State<HagridState>) -> Option<NamedFile> {
    NamedFile::open(state.assets_dir.join(file)).ok()
}

#[get("/")]
fn root() -> MyResponse {
    MyResponse::ok_bare("index")
}

#[get("/about")]
fn about() -> MyResponse {
    MyResponse::ok_bare("about/about")
}

#[get("/about/news")]
fn news() -> MyResponse {
    MyResponse::ok_bare("about/news")
}

#[get("/atom.xml")]
fn news_atom() -> MyResponse {
    MyResponse::xml("atom")
}

#[get("/about/faq")]
fn faq() -> MyResponse {
    MyResponse::ok_bare("about/faq")
}

#[get("/about/usage")]
fn usage() -> MyResponse {
    MyResponse::ok_bare("about/usage")
}

#[get("/about/privacy")]
fn privacy() -> MyResponse {
    MyResponse::ok_bare("about/privacy")
}

#[get("/about/api")]
fn apidoc() -> MyResponse {
    MyResponse::ok_bare("about/api")
}

#[get("/about/stats")]
fn stats() -> MyResponse {
    MyResponse::ok_bare("about/stats")
}

#[get("/errors/<code>/<template>")]
fn errors(
    i18n: I18n,
    origin: RequestOrigin,
    code: u16,
    template: String,
) -> Result<Custom<Template>> {
    if !template.chars().all(|x| x == '-' || char::is_ascii_alphabetic(&x)) {
        return Err(failure::err_msg("bad request"));
    }
    let status_code = Status::from_code(code)
        .ok_or(failure::err_msg("bad request"))?;
    let response_body = Template::render(
        format!("errors/{}-{}", code, template),
        templates::HagridLayout::new(templates::Bare{dummy: ()}, i18n, origin)
    );
    Ok(Custom(status_code, response_body))
}

pub fn serve() -> Result<()> {
    Err(rocket_factory(rocket::ignite())?.launch().into())
}

compile_i18n!();

fn rocket_factory(mut rocket: rocket::Rocket) -> Result<rocket::Rocket> {
    let routes = routes![
        // infra
        root,
        about,
        news,
        news_atom,
        privacy,
        apidoc,
        faq,
        usage,
        files,
        stats,
        errors,
        // VKSv1
        vks_api::vks_v1_by_email,
        vks_api::vks_v1_by_fingerprint,
        vks_api::vks_v1_by_keyid,
        vks_api::upload_json,
        vks_api::upload_fallback,
        vks_api::request_verify_json,
        vks_api::request_verify_fallback,
        // User interaction.
        vks_web::search,
        vks_web::upload,
        vks_web::upload_post_form,
        vks_web::upload_post_form_data,
        vks_web::request_verify_form,
        vks_web::request_verify_form_data,
        vks_web::verify_confirm,
        vks_web::verify_confirm_form,
        vks_web::quick_upload,
        vks_web::quick_upload_proceed,
        // Debug
        debug_web::debug_info,
        // HKP
        hkp::pks_lookup,
        hkp::pks_add_form,
        hkp::pks_add_form_data,
        hkp::pks_internal_index,
        // EManage
        manage::vks_manage,
        manage::vks_manage_key,
        manage::vks_manage_post,
        manage::vks_manage_unpublish,
        // Maintenance error page
        maintenance::maintenance_error_web,
        maintenance::maintenance_error_json,
        maintenance::maintenance_error_plain,
    ];

    let db_service = configure_db_service(rocket.config())?;
    let hagrid_state = configure_hagrid_state(rocket.config())?;
    let stateful_token_service = configure_stateful_token_service(rocket.config())?;
    let stateless_token_service = configure_stateless_token_service(rocket.config())?;
    let mail_service = configure_mail_service(rocket.config())?;
    let rate_limiter = configure_rate_limiter(rocket.config())?;
    let maintenance_mode = configure_maintenance_mode(rocket.config())?;
    let localized_template_list = configure_localized_template_list(rocket.config())?;
    println!("{:?}", localized_template_list);

    let prometheus = configure_prometheus(rocket.config());

    rocket = rocket
       .attach(Template::custom(|engines: &mut Engines| {
           let i18ns = include_i18n!();
           let i18n_helper = I18NHelper::new(i18ns);
           engines.handlebars.register_helper("text", Box::new(i18n_helper));
       }))
       .attach(maintenance_mode)
       .manage(include_i18n!())
       .manage(hagrid_state)
       .manage(stateless_token_service)
       .manage(stateful_token_service)
       .manage(mail_service)
       .manage(db_service)
       .manage(rate_limiter)
       .manage(localized_template_list)
       .mount("/", routes);

    if let Some(prometheus) = prometheus {
        rocket = rocket
            .attach(prometheus.clone())
            .mount("/metrics", prometheus);
    }

    Ok(rocket)
}

fn configure_prometheus(config: &Config) -> Option<PrometheusMetrics> {
    if !config.get_bool("enable_prometheus").unwrap_or(false) {
        return None;
    }
    let prometheus = PrometheusMetrics::new();
    counters::register_counters(&prometheus.registry());
    return Some(prometheus);
}

fn configure_db_service(config: &Config) -> Result<KeyDatabase> {
    let keys_internal_dir: PathBuf = config.get_str("keys_internal_dir")?.into();
    let keys_external_dir: PathBuf = config.get_str("keys_external_dir")?.into();
    let tmp_dir: PathBuf = config.get_str("tmp_dir")?.into();

    let fs_db = KeyDatabase::new(keys_internal_dir, keys_external_dir, tmp_dir)?;
    Ok(fs_db)
}

fn configure_hagrid_state(config: &Config) -> Result<HagridState> {
    let assets_dir: PathBuf = config.get_str("assets_dir")?.into();
    let keys_external_dir: PathBuf = config.get_str("keys_external_dir")?.into();
    let x_accel_prefix: Option<PathBuf> =
        config.get_string("x_accel_prefix").map(|prefix| prefix.into()).ok();

    // State
    let base_uri = config.get_str("base-URI")?.to_string();
    let base_uri_onion = config.get_str("base-URI-Onion")
        .map(|c| c.to_string())
        .unwrap_or(base_uri.clone());
    Ok(HagridState {
        assets_dir,
        keys_external_dir: keys_external_dir,
        base_uri,
        base_uri_onion,
        x_accel_redirect: config.get_bool("x-accel-redirect")?,
        x_accel_prefix,
    })
}

fn configure_stateful_token_service(config: &Config) -> Result<database::StatefulTokens> {
    let token_dir: PathBuf = config.get_str("token_dir")?.into();
    database::StatefulTokens::new(token_dir)
}

fn configure_stateless_token_service(config: &Config) -> Result<tokens::Service> {
    use std::convert::TryFrom;

    let secret = config.get_str("token_secret")?.to_string();
    let validity = config.get_int("token_validity")?;
    let validity = u64::try_from(validity)?;
    Ok(tokens::Service::init(&secret, validity))
}

fn configure_mail_service(config: &Config) -> Result<mail::Service> {
    // Mail service
    let email_template_dir: PathBuf = config.get_str("email_template_dir")?.into();

    let base_uri = config.get_str("base-URI")?.to_string();
    let from = config.get_str("from")?.to_string();

    let filemail_into = config.get_str("filemail_into")
        .ok().map(|p| PathBuf::from(p));

    if let Some(path) = filemail_into {
        mail::Service::filemail(from, base_uri, email_template_dir, path)
    } else {
        mail::Service::sendmail(from, base_uri, email_template_dir)
    }
}

fn configure_rate_limiter(config: &Config) -> Result<RateLimiter> {
    let timeout_secs = config.get_int("mail_rate_limit").unwrap_or(60);
    let timeout_secs = timeout_secs.try_into()?;
    Ok(RateLimiter::new(timeout_secs))
}

fn configure_localized_template_list(config: &Config) -> Result<TemplateOverrides> {
    let template_dir: PathBuf = config.get_str("template_dir")?.into();
    TemplateOverrides::load(&template_dir, "localized")
}

fn configure_maintenance_mode(config: &Config) -> Result<MaintenanceMode> {
    let maintenance_file: PathBuf = config.get_str("maintenance_file")
        .unwrap_or("maintenance").into();
    Ok(MaintenanceMode::new(maintenance_file))
}

#[cfg(test)]
pub mod tests {
    use regex;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::{tempdir, TempDir};
    use super::rocket;
    use rocket::local::{Client, LocalResponse};
    use rocket::http::Status;
    use rocket::http::ContentType;
    use lettre::Envelope;

    use sequoia_openpgp::TPK;
    use sequoia_openpgp::tpk::TPKBuilder;
    use sequoia_openpgp::parse::Parse;
    use sequoia_openpgp::serialize::Serialize;

    use crate::database::*;
    use super::*;

    // for some reason, this is no longer public in lettre itself
    // FIXME replace with builtin struct on lettre update
    // see https://github.com/lettre/lettre/blob/master/lettre/src/file/mod.rs#L41
    #[derive(Deserialize)]
    struct SerializableEmail {
        #[serde(alias = "envelope")]
        _envelope: Envelope,
        #[serde(alias = "message_id")]
        _message_id: String,
        message: Vec<u8>,
    }

    /// Fake base URI to use in tests.
    const BASE_URI: &'static str = "http://local.connection";
    const BASE_URI_ONION: &'static str = "http://local.connection.onion";

    /// Creates a configuration and empty state dir for testing purposes.
    ///
    /// Note that you need to keep the returned TempDir alive for the
    /// duration of your test.  To debug the test, mem::forget it to
    /// prevent cleanup.
    pub fn configuration() -> Result<(TempDir, rocket::Config)> {
        use rocket::config::Environment;

        let root = tempdir()?;
        let filemail = root.path().join("filemail");
        ::std::fs::create_dir_all(&filemail)?;

        let base_dir: PathBuf = root.path().into();

        let config = Config::build(Environment::Staging)
            .root(root.path().to_path_buf())
            .extra("template_dir",
                   ::std::env::current_dir().unwrap().join("dist/templates")
                   .to_str().unwrap())
            .extra("email_template_dir",
                   ::std::env::current_dir().unwrap().join("dist/email-templates")
                   .to_str().unwrap())
            .extra("assets_dir",
                   ::std::env::current_dir().unwrap().join("dist/assets")
                   .to_str().unwrap())
            .extra("keys_internal_dir", base_dir.join("keys_internal").to_str().unwrap())
            .extra("keys_external_dir", base_dir.join("keys_external").to_str().unwrap())
            .extra("tmp_dir", base_dir.join("tmp").to_str().unwrap())
            .extra("token_dir", base_dir.join("tokens").to_str().unwrap())
            .extra("maintenance_file", base_dir.join("maintenance").to_str().unwrap())
            .extra("base-URI", BASE_URI)
            .extra("base-URI-Onion", BASE_URI_ONION)
            .extra("from", "from@example.com")
            .extra("token_secret", "hagrid")
            .extra("token_validity", 3600)
            .extra("filemail_into", filemail.into_os_string().into_string()
                   .expect("path is valid UTF8"))
            .extra("x-accel-redirect", false)
            .finalize()?;
        Ok((root, config))
    }

    pub fn client() -> Result<(TempDir, Client)> {
        let (tmpdir, config) = configuration()?;
        let rocket = rocket_factory(rocket::custom(config))?;
        Ok((tmpdir, Client::new(rocket)?))
    }

    #[cfg(test)]
    pub fn assert_consistency(rocket: &rocket::Rocket) {
        let db = rocket.state::<KeyDatabase>().unwrap();
        db.check_consistency().unwrap();
    }

    #[test]
    fn about_translation() {
        let (_tmpdir, config) = configuration().unwrap();
        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let mut response = client.get("/about")
            .header(Header::new("Accept-Language", "de"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        // TODO check translation
        assert!(response.body_string().unwrap().contains("Hagrid"));
    }

    #[test]
    fn basics() {
        let (_tmpdir, config) = configuration().unwrap();
        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let mut response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Hagrid"));

        // Check that we see the privacy policy.
        let mut response = client.get("/about").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("distribution and discovery"));

        // Check that we see the privacy policy.
        let mut response = client.get("/about/privacy").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Public Key Data"));

        // Check that we see the API docs.
        let mut response = client.get("/about/api").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("/vks/v1/by-keyid"));

        // Check that we see the upload form.
        let mut response = client.get("/upload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("upload"));

        // Check that we see the deletion form.
        let mut response = client.get("/manage").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("any verified email address"));

        assert_consistency(client.rocket());
    }

    #[test]
    fn maintenance() {
        let (tmpdir, client) = client().unwrap();

        let maintenance_path = tmpdir.path().join("maintenance");
        let mut file = File::create(&maintenance_path).unwrap();
        file.write_all(b"maintenance-message").unwrap();

        // Check that endpoints return a maintenance message
        check_maintenance(&client, "/upload", ContentType::HTML);
        check_maintenance(&client, "/manage", ContentType::HTML);
        check_maintenance(&client, "/verify", ContentType::HTML);
        check_maintenance(&client, "/pks/add", ContentType::Plain);
        check_maintenance(&client, "/vks/v1/upload", ContentType::JSON);
        check_maintenance(&client, "/vks/v1/request-verify", ContentType::JSON);

        // Extra check for the shortcut "PUT" endpoint
        let mut response = client.put("/").dispatch();
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.content_type(), Some(ContentType::Plain));
        assert!(response.body_string().unwrap().contains("maintenance-message"));

        fs::remove_file(&maintenance_path).unwrap();
        // Check that we see the upload form.
        let mut response = client.get("/upload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(!response.body_string().unwrap().contains("maintenance-message"));
    }

    fn check_maintenance(client: &Client, uri: &str, content_type: ContentType) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::ServiceUnavailable);
        assert_eq!(response.content_type(), Some(content_type));
        assert!(response.body_string().unwrap().contains("maintenance-message"));
    }

    #[test]
    fn upload_verify_single() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        // Check the verification link
        check_verify_link(&client, &token, "foo@invalid.example.com", "");

        // Now check for the verification mail.
        check_mails_and_verify_email(&client, filemail_into.as_path());

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk, 1);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 1);

        // Request deletion of the binding.
        vks_manage(&client, "foo@invalid.example.com");

        // Confirm deletion.
        check_mails_and_confirm_deletion(&client, filemail_into.as_path(), "foo@invalid.example.com");

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_verify_lang() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        check_verify_link(&client, &token, "foo@invalid.example.com", "de");
        let mail_content = pop_mail(&filemail_into).unwrap().unwrap();
        assert!(mail_content.contains("Dies ist eine automatisierte Nachricht"));
        assert!(mail_content.contains("Subject: =?utf-8?q?Best=C3=A4tige?= foo@invalid.example.com\r\n\t=?utf-8?q?f=C3=BCr?= deinen =?utf-8?q?Schl=C3=BCssel?= auf local.connection"));
    }

    #[test]
    fn upload_two() {
        let (_tmpdir, config) = configuration().unwrap();

        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Generate two keys and upload them.
        let tpk_0 = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap().0;
        let tpk_1 = TPKBuilder::autocrypt(
            None, Some("bar@invalid.example.com"))
            .generate().unwrap().0;

        let mut tpk_serialized = Vec::new();
        tpk_0.serialize(&mut tpk_serialized).unwrap();
        tpk_1.serialize(&mut tpk_serialized).unwrap();
        vks_publish_submit_multiple(&client, &tpk_serialized);

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
    }

    #[test]
    fn upload_verify_two() {
        let (tmpdir, config) = configuration().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        let rocket = rocket_factory(rocket::custom(config)).unwrap();
        let client = Client::new(rocket).expect("valid rocket instance");

        // Generate two keys and upload them.
        let tpk_1 = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap().0;
        let tpk_2 = TPKBuilder::autocrypt(
            None, Some("bar@invalid.example.com"))
            .generate().unwrap().0;

        let mut tpk_serialized_1 = Vec::new();
        tpk_1.serialize(&mut tpk_serialized_1).unwrap();
        let token_1 = vks_publish_submit_get_token(&client, &tpk_serialized_1);

        let mut tpk_serialized_2 = Vec::new();
        tpk_2.serialize(&mut tpk_serialized_2).unwrap();
        let token_2 = vks_publish_json_get_token(&client, &tpk_serialized_2);

        // Prior to email confirmation, we should not be able to look
        // them up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // And check that we can get them back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_2, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_2, 0);

        // Check the verification link
        check_verify_link(&client, &token_1, "foo@invalid.example.com", "");
        check_verify_link_json(&client, &token_2, "bar@invalid.example.com");

        // Now check for the verification mails.
        check_mails_and_verify_email(&client, &filemail_into);
        check_mails_and_verify_email(&client, &filemail_into);

        // Now lookups using the mail address should work.
        check_responses_by_email(&client, "foo@invalid.example.com", &tpk_1, 1);
        check_responses_by_email(&client, "bar@invalid.example.com", &tpk_2, 1);

        // Request deletion of the bindings.
        vks_manage(&client, "foo@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "foo@invalid.example.com");
        vks_manage(&client, "bar@invalid.example.com");
        check_mails_and_confirm_deletion(&client, &filemail_into, "bar@invalid.example.com");

        // Now, we should no longer be able to look it up by email
        // address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");
        check_null_responses_by_email(&client, "bar@invalid.example.com");

        // But lookup by fingerprint should still work.
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_2, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_2, 0);

        assert_consistency(client.rocket());
    }

    #[test]
    fn upload_no_key() {
        let (_tmpdir, client) = client().unwrap();
        let response = vks_publish_submit_response(&client, b"");
        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn upload_verify_onion() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate a key and upload it.
        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();
        let token = vks_publish_submit_get_token(&client, &tpk_serialized);

        // Check the verification link
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", &token)
            .append_pair("address", "foo@invalid.example.com")
            .finish();

        let response = client.post("/upload/request-verify")
            .header(ContentType::Form)
            .header(Header::new("X-Is-Onion", "true"))
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // Now check for the verification mail.
        let pattern = format!("{}(/verify/[^ \t\n]*)", BASE_URI_ONION);
        let confirm_uri = pop_mail_capture_pattern(&filemail_into, &pattern);

        let response = client.get(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);

        assert_consistency(client.rocket());
    }


    #[test]
    fn upload_curl_shortcut() {
        let (_tmpdir, client) = client().unwrap();

        let (tpk, _) = TPKBuilder::autocrypt(
            None, Some("foo@invalid.example.com"))
            .generate().unwrap();

        let mut tpk_serialized = Vec::new();
        tpk.serialize(&mut tpk_serialized).unwrap();

        let _token = vks_publish_shortcut_get_token(&client, &tpk_serialized);

        check_mr_responses_by_fingerprint(&client, &tpk, 0);
        check_null_responses_by_email(&client, "foo@invalid.example.com");
    }

    #[test]
    fn search_invalid() {
        let (_tmpdir, client) = client().unwrap();
        check_response(&client, "/search?q=0x1234abcd",
                       Status::BadRequest, "not supported, sorry!");
        check_response(&client, "/search?q=1234abcd",
                       Status::BadRequest, "not supported, sorry!");
        check_response(&client, "/pks/lookup?op=get&search=0x1234abcd",
                       Status::BadRequest, "not supported, sorry!");
        check_response(&client, "/pks/lookup?op=get&search=1234abcd",
                       Status::BadRequest, "not supported, sorry!");

    }

    /// Asserts that the given URI 404s.
    pub fn check_null_response(client: &Client, uri: &str) {
        let response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::NotFound);
    }

    /// Asserts that lookups by the given email 404.
    pub fn check_null_responses_by_email(client: &Client, addr: &str) {
        check_null_response(
            &client, &format!("/vks/v1/by-email/{}", addr));
        check_null_response(
            &client, &format!("/pks/lookup?op=get&search={}", addr));
        check_null_response(
            &client, &format!("/pks/lookup?op=get&options=mr&search={}",
                              addr));
    }

    /// Asserts that lookups by the given email are successful.
    pub fn check_responses_by_email(client: &Client, addr: &str, tpk: &TPK,
                                    nr_uids: usize) {
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/vks/v1/by-email/{}", addr.replace("@", "%40")),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", addr),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/search?q={}", addr),
            &tpk, nr_uids);
        check_hr_response_onion(
            &client,
            &format!("/search?q={}", addr),
            &tpk, nr_uids);
    }

    /// Asserts that the given URI returns a TPK matching the given
    /// one, with the given number of userids.
    pub fn check_mr_response(client: &Client, uri: &str, tpk: &TPK,
                             nr_uids: usize) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(),
                   Some(ContentType::new("application", "pgp-keys")));
        let body = response.body_string().unwrap();
        assert!(body.contains("END PGP PUBLIC KEY BLOCK"));
        let tpk_ = TPK::from_bytes(body.as_bytes()).unwrap();
        assert_eq!(tpk.fingerprint(), tpk_.fingerprint());
        assert_eq!(tpk.subkeys().map(|skb| skb.subkey().fingerprint())
                   .collect::<Vec<_>>(),
                   tpk_.subkeys().map(|skb| skb.subkey().fingerprint())
                   .collect::<Vec<_>>());
        assert_eq!(tpk_.userids().count(), nr_uids);
    }

        // it's a rather "reverse implementation" style test.. can we do better?
    /// Asserts that the given URI returns a correct hkp "index"
    /// response for the given TPK.
    pub fn check_index_response(client: &Client, uri: &str, tpk: &TPK) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(),
                   Some(ContentType::new("text", "plain")));
        let body = response.body_string().unwrap();

        assert!(body.contains("info:1:1"));
        let primary_fpr = tpk.fingerprint().to_hex();
        let algo: u8 = tpk.primary().pk_algo().into();
        assert!(body.contains(&format!("pub:{}:{}:", primary_fpr, algo)));

        let creation_time = tpk.primary().creation_time().to_timespec().sec;
        assert!(body.contains(&format!(":{}:", creation_time)));
    }

    /// Asserts that we can get the given TPK back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_mr_responses_by_fingerprint(client: &Client, tpk: &TPK,
                                             nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = tpk.fingerprint().to_keyid().to_hex();

        check_mr_response(
            &client, &format!("/vks/v1/by-keyid/{}", keyid), &tpk, nr_uids);
        check_mr_response(
            &client, &format!("/vks/v1/by-fingerprint/{}", fp), &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", fp),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", fp),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search={}", keyid),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&options=mr&search=0x{}", keyid),
            &tpk, nr_uids);
        check_mr_response(
            &client,
            &format!("/pks/lookup?op=get&search=0x{}", keyid),
            &tpk, nr_uids);

        check_index_response(
            &client,
            &format!("/pks/lookup?op=index&search={}", fp),
            &tpk);
    }

    /// Asserts that the given URI contains the search string.
    pub fn check_response(client: &Client, uri: &str, status: Status, needle: &str) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), status);
        let body = response.body_string().unwrap();
        println!("{}", body);
        assert!(body.contains(needle));
    }

    /// Asserts that the given URI returns human readable response
    /// page that contains a URI pointing to the TPK.
    pub fn check_hr_response(client: &Client, uri: &str, tpk: &TPK,
                             nr_uids: usize) {
        let mut response = client.get(uri).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        let body = response.body_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));

        // Extract the links.
        let link_re = regex::Regex::new(
            &format!("{}(/vks/[^ \t\n\"<]*)", BASE_URI)).unwrap();
        let mut n = 0;
        for link in link_re.captures_iter(&body) {
            check_mr_response(client, link.get(1).unwrap().as_str(), tpk,
                              nr_uids);
            n += 1;
        }
        assert!(n > 0);
    }

    /// Asserts that the given URI returns human readable response
    /// page that contains an onion URI pointing to the TPK.
    pub fn check_hr_response_onion(client: &Client, uri: &str, tpk: &TPK,
                             _nr_uids: usize) {
        let mut response = client
            .get(uri)
            .header(Header::new("X-Is-Onion", "true"))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.body_string().unwrap();
        assert!(body.contains("found"));
        assert!(body.contains(&tpk.fingerprint().to_hex()));

        // Extract the links.
        let link_re = regex::Regex::new(
            &format!("{}(/vks/[^ \t\n\"<]*)", BASE_URI_ONION)).unwrap();
        assert!(link_re.is_match(&body));
    }


    /// Asserts that we can get the given TPK back using the various
    /// by-fingerprint or by-keyid lookup mechanisms.
    pub fn check_hr_responses_by_fingerprint(client: &Client, tpk: &TPK,
                                             nr_uids: usize) {
        let fp = tpk.fingerprint().to_hex();
        let keyid = tpk.fingerprint().to_keyid().to_hex();

        check_hr_response(
            &client,
            &format!("/search?q={}", fp),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/search?q=0x{}", fp),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/search?q={}", keyid),
            &tpk, nr_uids);
        check_hr_response(
            &client,
            &format!("/search?q=0x{}", keyid),
            &tpk, nr_uids);
    }

    fn check_verify_link(client: &Client, token: &str, address: &str, lang: &'static str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("address", address)
            .finish();

        let response = client.post("/upload/request-verify")
            .header(ContentType::Form)
            .header(Header::new("Accept-Language", lang))
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn check_verify_link_json(client: &Client, token: &str, address: &str) {
        let json = format!(r#"{{"token":"{}","addresses":["{}"]}}"#, token, address);

        let mut response = client.post("/vks/v1/request-verify")
            .header(ContentType::JSON)
            .body(json.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.body_string().unwrap().contains("pending"));
    }

    fn check_mails_and_verify_email(client: &Client, filemail_path: &Path) {
        let pattern = format!("{}(/verify/[^ \t\n]*)", BASE_URI);
        let confirm_uri = pop_mail_capture_pattern(filemail_path, &pattern);

        let response = client.post(&confirm_uri).dispatch();
        assert_eq!(response.status(), Status::Ok);

        let mut response_second = client.post(&confirm_uri).dispatch();
        assert_eq!(response_second.status(), Status::BadRequest);
        assert!(response_second.body_string().unwrap().contains("already been verified"));
    }

    fn check_mails_and_confirm_deletion(client: &Client, filemail_path: &Path, address: &str) {
        let pattern = format!("{}/manage/([^ \t\n]*)", BASE_URI);
        let token = pop_mail_capture_pattern(filemail_path, &pattern);
        vks_manage_delete(client, &token, address);
    }

    fn pop_mail_capture_pattern(filemail_path: &Path, pattern: &str) -> String {
        let mail_content = pop_mail(filemail_path).unwrap().unwrap();

        let capture_re = regex::bytes::Regex::new(pattern).unwrap();
        let capture_content = capture_re.captures(mail_content.as_ref()).unwrap()
            .get(1).unwrap().as_bytes();
        String::from_utf8_lossy(capture_content).to_string()
    }

    /// Returns and removes the first mail it finds from the given
    /// directory.
    pub fn pop_mail(dir: &Path) -> Result<Option<String>> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let fh = fs::File::open(entry.path())?;
                fs::remove_file(entry.path())?;
                let mail: SerializableEmail = ::serde_json::from_reader(fh)?;
                let body = String::from_utf8_lossy(&mail.message).to_string();
                return Ok(Some(body));
            }
        }
        Ok(None)
    }

    fn vks_publish_submit_multiple<'a>(client: &'a Client, data: &[u8]) {
        let mut response = vks_publish_submit_response(client, data);
        let response_body = response.body_string().unwrap();

        assert_eq!(response.status(), Status::Ok);
        assert!(response_body.contains("you must upload them individually"));
    }

    fn vks_publish_submit_get_token<'a>(client: &'a Client, data: &[u8]) -> String {
        let mut response = vks_publish_submit_response(client, data);
        let response_body = response.body_string().unwrap();

        let pattern = "name=\"token\" value=\"([^\"]*)\"";
        let capture_re = regex::bytes::Regex::new(pattern).unwrap();
        let capture_content = capture_re .captures(response_body.as_bytes()).unwrap()
            .get(1).unwrap().as_bytes();
        let token = String::from_utf8_lossy(capture_content).to_string();

        assert_eq!(response.status(), Status::Ok);
        token
    }

    fn vks_publish_submit_response<'a>(client: &'a Client, data: &[u8]) ->
            LocalResponse<'a> {
        let ct = ContentType::with_params(
            "multipart", "form-data",
            ("boundary", "---------------------------14733842173518794281682249499"));

        let header =
            b"-----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"csrf\"\r\n\
              \r\n\
              \r\n\
              -----------------------------14733842173518794281682249499\r\n\
              Content-Disposition: form-data; name=\"keytext\"; filename=\".k\"\r\n\
              Content-Type: application/octet-stream\r\n\
              \r\n";
        let footer = b"\r\n-----------------------------14733842173518794281682249499--";

        let mut body = Vec::new();
        body.extend_from_slice(header);
        body.extend_from_slice(data);
        body.extend_from_slice(footer);
        client.post("/upload/submit")
            .header(ct)
            .body(&body[..])
            .dispatch()
    }

    fn vks_publish_shortcut_get_token<'a>(client: &'a Client, data: &[u8]) -> String {
        let mut response = client.put("/")
            .body(data)
            .dispatch();
        let response_body = response.body_string().unwrap();
        assert_eq!(response.status(), Status::Ok);
        assert!(response_body.contains("Key successfully uploaded"));

        let pattern = format!("{}/upload/([^ \t\n]*)", BASE_URI);
        let capture_re = regex::bytes::Regex::new(&pattern).unwrap();
        let capture_content = capture_re .captures(response_body.as_bytes()).unwrap()
            .get(1).unwrap().as_bytes();
        String::from_utf8_lossy(capture_content).to_string()
    }

    fn vks_publish_json_get_token<'a>(client: &'a Client, data: &[u8]) -> String {
        let mut response = client.post("/vks/v1/upload")
            .header(ContentType::JSON)
            .body(format!(r#"{{ "keytext": "{}" }}"#, base64::encode(data)))
            .dispatch();
        let response_body = response.body_string().unwrap();
        let result: vks_api::json::UploadResult  = serde_json::from_str(&response_body).unwrap();

        assert_eq!(response.status(), Status::Ok);
        result.token
    }

    fn vks_manage<'a>(client: &'a Client, search_term: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("search_term", search_term)
            .finish();
        let response = client.post("/manage")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }

    fn vks_manage_delete(client: &Client, token: &str, address: &str) {
        let encoded = ::url::form_urlencoded::Serializer::new(String::new())
            .append_pair("token", token)
            .append_pair("address", address)
            .finish();
        let response = client.post("/manage/unpublish")
            .header(ContentType::Form)
            .body(encoded.as_bytes())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
    }
}
