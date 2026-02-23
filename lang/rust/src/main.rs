use std::fs;
use std::process::Command;
fn main() {
    let ifaces: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|e| e.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().to_string()).filter(|n| n != "lo").collect())
        .unwrap_or_else(|_| vec!["eth0".into()]);
    for i in &ifaces {
        let _ = Command::new("ip").args(["link","set",i,"up"]).status();
        if Command::new("dhclient").args(["-1","-q",i]).status().map(|s|s.success()).unwrap_or(false) { println!("{} up",i); }
    }
    let ok = Command::new("ping").args(["-c1","-W3","8.8.8.8"]).status().map(|s|s.success()).unwrap_or(false);
    println!("{}", if ok {"ONLINE"} else {"OFFLINE"});
    std::process::exit(if ok {0} else {1});
}
