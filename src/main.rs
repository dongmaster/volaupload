#![feature(collections,core,io,os)]

extern crate curl;
extern crate getopts;
extern crate "rustc-serialize" as rustc_serialize;

use std::old_io::Command;
use std::os;

use curl::http::handle as http;
use curl::http::Response;
use curl::ErrCode;
use getopts::Options;
use rustc_serialize::json::decode as json;

const SERVER : &'static str = "volafile.io";

#[derive(RustcDecodable, Debug)]
pub struct UploadKey { key: String, server: String, file_id: String }

#[derive(RustcDecodable, Debug)]
pub struct AuthCookie { session: String }

pub struct Session {
    room: String,
    user: String,
    cookie: Option<AuthCookie>
}

impl Session {
    fn new(room: &str, user: &str) -> Session {
        Session {
            room: room.to_string(),
            user: user.to_string(),
            cookie: None
        }
    }

    fn get(&self, url: &str) -> Result<Response, ErrCode> {
        let mut handle = http();
        let mut req = handle.get(url);
        req = match self.cookie {
            Some(ref cookie) => {
                req.header("Cookie", &format!("session={}", cookie.session))
            },
            _ => req
        };
        req.exec()
    }

    fn login(&mut self, passwd: &str) {
        match self.get(&format!("https://{}/rest/login?name={}&password={}",
                               SERVER, &self.user, passwd)) {
            Ok(resp) => {
                match resp.get_code() {
                    200 => {
                        self.cookie = json(
                            &String::from_utf8_lossy(resp.get_body())).unwrap();
                    },
                    x => panic!("Failed to login, invalid credentials: {}",
                                x)
                }
            }
            Err(err) => panic!("Failed to login: {}", err)
        }
    }

    fn upload_key(&self) -> UploadKey {
        let url = format!("https://{}/rest/getUploadKey?name={}&room={}",
                          SERVER, &self.user, &self.room);
        let resp = self.get(&url).unwrap();
        let body = String::from_utf8_lossy(&resp.get_body());
        
        if body.as_slice().contains("Invalid room") == true {
            panic!("\n    Room does not exist. Try a valid room instead.\n"); // Invalid room url
        }
        
        json(&body).unwrap()
    }
    
    fn upload(&self, file: &str) {
        let upload_key = self.upload_key();
        let upload_url = format!("https://{}/upload?room={}&key={}",
                                 upload_key.server, self.room, upload_key.key);
        let mut curl = Command::new("curl");
        curl.args(&["--header", "Origin: volafile.io"]);
        curl.arg("--form").arg(format!("file=@{}", file));
        curl.arg("--progress-bar");
        curl.arg(upload_url);

        println!("Uploading {} to {} as {}", file, self.room, self.user);
        match curl.output() {
            Ok(r)   => println!("File {} uploaded ({})", file, r.status),
            Err(e)  => panic!("failed to execute process: {}", e),
        };
    }
}

fn main() {
    let args = os::args();

    let mut opts = Options::new();
    opts.optopt("r", "room", "Upload to Room", "ROOM");
    opts.optopt("u", "user", "User name for uploads", "USER");
    opts.optopt("p", "password", "Authenticate user", "PASS");
    opts.optflag("h", "help", "Halp muh!");

    let brief = format!("Usage: {} [options]", args.first().unwrap());
    let usage = format!("{}", opts.usage(brief.as_slice()));

    let m = match opts.parse(args.tail()) {
        Ok(m) => m,
        Err(e) => panic!("You didn't call muh correctly!\n{}\n\n{}", e, usage)
    };
    
    if m.opt_present("h") {
        println!("{}", usage);
        println!("\nHow stupid are you that you need this?");
        return;
    }
    
    let room = match m.opt_str("r") {
        Some(x) => x,
        _       => panic!("You haven't specified a room!\n\n{}", usage)
    };
    
    let name = match m.opt_str("u") {
        Some(x) => x,
        _       => panic!("You haven't specified a user name!\n\n{}", usage)
    };
    
    let mut session = Session::new(&room, &name);
    
    match m.opt_str("p") {
        Some(x) => {
            println!("Logging in as {}", name);
            session.login(&x)
        },
        _ => {}
    };
    
    match &m.free {
        x if !x.is_empty() => {
            for file in x.iter() {
                session.upload(file);
            };
        }
        _ => panic!("You haven't specified a any files to upload!\n\n{}", usage)
    };
}
