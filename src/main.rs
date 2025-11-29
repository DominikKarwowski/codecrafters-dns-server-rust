use std::{env, process};

use codecrafters_dns_server::{DnsServerConfig, run_dns_server};

fn main() {
    println!("Logs from your program will appear here!");

    let config = DnsServerConfig::new(env::args());

    if let Err(err) = run_dns_server(&config) {
        eprintln!("Application error: {err}");
        process::exit(1);
    };
}
